// Copyright (C) 2026 Toit contributors.
// Use of this source code is governed by a Zero-Clause BSD license that can
// be found in the TESTS_LICENSE file.

import expect show *
import des show Des TripleDes BlockCipher cbc-encrypt cbc-decrypt
import nfc.reader show Target
import nfc.iso-dep show IsoDepCard
import des-fire show DesFireCard DesFireException DesFireFileSettings

main:
  test-get-version-chaining
  test-get-application-ids
  test-select-application-not-found
  test-free-memory
  test-authenticate-succeeds --key-size=8
  test-authenticate-succeeds --key-size=16
  test-authenticate-fails-with-wrong-key
  test-file-create-write-read-round-trip
  test-read-missing-file-throws
  test-get-file-settings
  test-exception-decoding

test-get-version-chaining:
  fake := FakeDesFirePicc
  card := DesFireCard (IsoDepCard fake)
  version := card.get-version
  expect-bytes-equal fake.version-bytes version

test-get-application-ids:
  fake := FakeDesFirePicc
  fake.aids = [0x000001, 0x0000AB]
  card := DesFireCard (IsoDepCard fake)
  expect-equals fake.aids card.get-application-ids

test-select-application-not-found:
  fake := FakeDesFirePicc
  fake.aids = [0x000001]
  card := DesFireCard (IsoDepCard fake)
  exception := catch: card.select-application 0x0000FF
  expect-equals DesFireException.APPLICATION-NOT-FOUND exception.status

test-free-memory:
  fake := FakeDesFirePicc
  fake.free-memory-bytes = 0x001234
  card := DesFireCard (IsoDepCard fake)
  expect-equals 0x001234 card.free-memory

test-authenticate-succeeds --key-size/int:
  key := ByteArray key-size: it
  fake := FakeDesFirePicc
  fake.key = key
  card := DesFireCard (IsoDepCard fake)
  expect-not card.is-authenticated
  card.authenticate --key-number=0 --key=key
  expect card.is-authenticated
  card.deauthenticate
  expect-not card.is-authenticated

test-authenticate-fails-with-wrong-key:
  // With a real card, a wrong key means the PICC itself rejects the
  // PCD's step-2 message (its decrypted RndB' won't match), so the
  // observable failure is an AUTHENTICATION_ERROR status, not the
  // PCD-side DESFIRE_AUTH_FAILED (which only fires if the PICC's own
  // reply happens to look valid despite the key mismatch).
  key := ByteArray 16: it
  wrong-key := ByteArray 16: 0xFF
  fake := FakeDesFirePicc
  fake.key = key
  card := DesFireCard (IsoDepCard fake)
  exception := catch: card.authenticate --key-number=0 --key=wrong-key
  expect-equals DesFireException.AUTHENTICATION-ERROR exception.status

test-file-create-write-read-round-trip:
  fake := FakeDesFirePicc
  card := DesFireCard (IsoDepCard fake)
  card.create-standard-data-file 3 --size=16
  data := #[1, 2, 3, 4, 5, 6, 7, 8]
  card.write-data 3 data --offset=2
  read-back := card.read-data 3 --offset=2 --size=data.size
  expect-bytes-equal data read-back

  card.delete-file 3
  exception := catch: card.read-data 3 --offset=0 --size=1
  expect-equals DesFireException.FILE-NOT-FOUND exception.status

test-read-missing-file-throws:
  fake := FakeDesFirePicc
  card := DesFireCard (IsoDepCard fake)
  exception := catch: card.read-data 9 --offset=0 --size=1
  expect-equals DesFireException.FILE-NOT-FOUND exception.status

test-get-file-settings:
  fake := FakeDesFirePicc
  card := DesFireCard (IsoDepCard fake)
  card.create-standard-data-file 5 --size=32 --communication-settings=0 --access-rights=0x1234
  settings := card.get-file-settings 5
  expect-equals DesFireFileSettings.TYPE-STANDARD-DATA settings.type
  expect-equals 0 settings.communication-settings
  expect-equals 0x1234 settings.access-rights
  expect-equals 32 settings.file-size

test-exception-decoding:
  expect-equals "DesFireException(FILE_NOT_FOUND, status=0xf0)" (DesFireException DesFireException.FILE-NOT-FOUND).stringify
  expect-equals "DesFireException(UNKNOWN, status=0x99)" (DesFireException 0x99).stringify

/**
Plays the PICC side of DESFire's native command set (just enough to
  exercise $DesFireCard: version/AID/file enumeration, the legacy
  DES/2K3DES authentication handshake with real session-key-independent
  crypto, and basic file storage), over plain ISO 14443-3 I/O — the
  I-block framing itself is `IsoDepCard`'s job, already verified
  independently in toit-nfc's own test suite, so this fake only needs to
  speak the native command/status layer above it.
*/
class FakeDesFirePicc implements Target:
  version-bytes/ByteArray := #[0x04, 0x01, 0x01, 0x00, 0x16, 0x05, 0x01, 0x04, 0x01, 0x01, 0x00, 0x16, 0x05, 0x01, 0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x01, 0x02, 0x03, 0x04, 0x05, 23, 1]
  aids/List := []
  free-memory-bytes/int := 0x002710
  key/ByteArray := ByteArray 16: it

  files_/Map := {:} // file-id -> {size, communication-settings, access-rights, data}
  chaining-remainder_/List := []
  rnd-b_/ByteArray? := null
  encrypted-rnd-b_/ByteArray? := null
  auth-cipher_/BlockCipher? := null

  uid -> ByteArray: return #[0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
  type -> int: return 0
  close -> none:

  transceive bytes/ByteArray --check-crc/bool=false -> ByteArray?:
    if bytes.size == 2 and bytes[0] == 0xE0: return #[0x01] // TL-only ATS.

    pcb := bytes[0]
    block-type := pcb & 0xC0
    if block-type == 0xC0: return bytes // DESELECT ack.

    inf := bytes[1 ..]
    native := handle-native_ inf
    send-block-number := pcb & 0x01
    return #[0x02 | send-block-number] + native

  handle-native_ inf/ByteArray -> ByteArray:
    code := inf[0]
    data := inf[1 ..]
    if code == 0x60: return chain_ version-bytes
    if code == 0x6A:
      bytes := #[]
      aids.do: | aid/int | bytes += #[aid & 0xFF, (aid >> 8) & 0xFF, (aid >> 16) & 0xFF]
      return bytes + #[0x00]
    if code == 0x5A:
      aid := data[0] | (data[1] << 8) | (data[2] << 16)
      if aid != 0 and not aids.contains aid: return #[0xA0]
      return #[0x00]
    if code == 0x6E:
      return #[free-memory-bytes & 0xFF, (free-memory-bytes >> 8) & 0xFF, (free-memory-bytes >> 16) & 0xFF, 0x00]
    if code == 0x0A: return authenticate-step1_ data
    if code == 0xAF:
      if data.is-empty: return continue-chain_
      return authenticate-step2_ data
    if code == 0xCD:
      file-id := data[0]
      files_[file-id] = {
        "communication-settings": data[1],
        "access-rights": data[2] | (data[3] << 8),
        "size": data[4] | (data[5] << 8) | (data[6] << 16),
        "data": ByteArray (data[4] | (data[5] << 8) | (data[6] << 16)),
      }
      return #[0x00]
    if code == 0xDF:
      files_.remove data[0]
      return #[0x00]
    if code == 0x6F:
      ids := []
      files_.do --keys: | id | ids.add id
      return (ByteArray ids.size: ids[it]) + #[0x00]
    if code == 0xF5:
      file := files_.get data[0]
      if not file: return #[0xF0]
      size := file["size"]
      return #[
        0x00, file["communication-settings"],
        file["access-rights"] & 0xFF, (file["access-rights"] >> 8) & 0xFF,
        size & 0xFF, (size >> 8) & 0xFF, (size >> 16) & 0xFF,
        0x00,
      ]
    if code == 0xBD:
      file-id := data[0]
      file := files_.get file-id
      if not file: return #[0xF0]
      offset := data[1] | (data[2] << 8) | (data[3] << 16)
      size := data[4] | (data[5] << 8) | (data[6] << 16)
      return file["data"][offset .. offset + size] + #[0x00]
    if code == 0x3D:
      file-id := data[0]
      file := files_.get file-id
      if not file: return #[0xF0]
      offset := data[1] | (data[2] << 8) | (data[3] << 16)
      size := data[4] | (data[5] << 8) | (data[6] << 16)
      payload := data[7 ..]
      stored := file["data"]
      stored.replace offset payload[.. size]
      return #[0x00]
    throw "Unhandled native command in fake: 0x$(%02x code)"

  chain_ bytes/ByteArray -> ByteArray:
    // Splits into 3 roughly-equal chained frames, matching GetVersion's
    // real 3-part structure closely enough to exercise command_'s
    // additional-frame reassembly. The remaining chunks are served one
    // at a time by $continue-chain_ as bare 0xAF continuations arrive.
    third := bytes.size / 3
    chunks := [bytes[.. third], bytes[third .. 2 * third], bytes[2 * third ..]]
    chaining-remainder_ = chunks[1 ..]
    return chunks[0] + #[0xAF]

  continue-chain_ -> ByteArray:
    if chaining-remainder_.is-empty: throw "Unexpected chain continuation"
    chunk := chaining-remainder_[0]
    chaining-remainder_ = chaining-remainder_[1 ..]
    is-last := chaining-remainder_.is-empty
    return chunk + #[is-last ? 0x00 : 0xAF]

  authenticate-step1_ data/ByteArray -> ByteArray:
    cipher := key.size == 8 ? (Des --key=key) : (TripleDes --key=key)
    auth-cipher_ = cipher
    rnd-b_ = ByteArray 8: random 0x100
    encrypted-rnd-b_ = cbc-encrypt cipher rnd-b_
    return encrypted-rnd-b_ + #[0xAF]

  authenticate-step2_ data/ByteArray -> ByteArray:
    cipher := auth-cipher_
    plain := cbc-decrypt cipher data --iv=encrypted-rnd-b_
    rnd-a := plain[.. 8]
    received-rnd-b-rotated := plain[8 ..]
    expected-rnd-b-rotated := rnd-b_[1 ..] + rnd-b_[.. 1]
    if received-rnd-b-rotated != expected-rnd-b-rotated: return #[0xAE]

    rnd-a-rotated := rnd-a[1 ..] + rnd-a[.. 1]
    encrypted := cbc-encrypt cipher rnd-a-rotated --iv=data[8 .. 16]
    return encrypted + #[0x00]
