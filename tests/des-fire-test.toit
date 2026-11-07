// Copyright (C) 2026 Toit contributors.
// Use of this source code is governed by a Zero-Clause BSD license that can
// be found in the TESTS_LICENSE file.

import expect show *
import crypto.aes show AesEcb
import crypto.crc show crc-a
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
  test-maced-write-read-round-trip
  test-enciphered-write-read-round-trip
  test-maced-write-rejected-without-authentication
  test-maced-read-detects-tampering
  test-authenticate-iso-succeeds
  test-authenticate-iso-fails-with-wrong-key
  test-authenticate-aes-succeeds
  test-authenticate-aes-fails-with-wrong-key

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

test-maced-write-read-round-trip:
  key := ByteArray 16: it
  fake := FakeDesFirePicc
  fake.key = key
  card := DesFireCard (IsoDepCard fake)
  card.authenticate --key-number=0 --key=key
  card.create-standard-data-file 3 --size=16 --communication-settings=DesFireCard.COMMUNICATION-MACED
  data := #[1, 2, 3, 4, 5, 6, 7, 8]
  card.write-data 3 data --offset=2 --communication-settings=DesFireCard.COMMUNICATION-MACED
  read-back := card.read-data 3 --offset=2 --size=data.size --communication-settings=DesFireCard.COMMUNICATION-MACED
  expect-bytes-equal data read-back

test-enciphered-write-read-round-trip:
  key := ByteArray 8: it
  fake := FakeDesFirePicc
  fake.key = key
  card := DesFireCard (IsoDepCard fake)
  card.authenticate --key-number=0 --key=key
  card.create-standard-data-file 4 --size=16 --communication-settings=DesFireCard.COMMUNICATION-ENCIPHERED
  data := #[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22]
  card.write-data 4 data --offset=1 --communication-settings=DesFireCard.COMMUNICATION-ENCIPHERED
  read-back := card.read-data 4 --offset=1 --size=data.size --communication-settings=DesFireCard.COMMUNICATION-ENCIPHERED
  expect-bytes-equal data read-back

test-maced-write-rejected-without-authentication:
  fake := FakeDesFirePicc
  card := DesFireCard (IsoDepCard fake)
  exception := catch: card.write-data 3 #[1, 2, 3] --communication-settings=DesFireCard.COMMUNICATION-MACED
  expect-equals "DESFIRE_NOT_AUTHENTICATED" exception

test-maced-read-detects-tampering:
  // Deliberate corruption: a file declared Plain but read back as if it
  // were MACed won't have a real trailing MAC, so the (wrong) 4 trailing
  // data bytes used as a "MAC" should essentially never match -- proving
  // $DesFireCard.read-data actually checks the MAC rather than passing
  // data through unconditionally.
  key := ByteArray 16: it
  fake := FakeDesFirePicc
  fake.key = key
  card := DesFireCard (IsoDepCard fake)
  card.authenticate --key-number=0 --key=key
  card.create-standard-data-file 6 --size=16 --communication-settings=DesFireCard.COMMUNICATION-PLAIN
  card.write-data 6 #[1, 2, 3, 4, 5, 6, 7, 8] --offset=0
  exception := catch: card.read-data 6 --offset=0 --size=8 --communication-settings=DesFireCard.COMMUNICATION-MACED
  expect-equals "DESFIRE_AUTH_FAILED" exception

test-authenticate-iso-succeeds:
  key := ByteArray 24: it
  fake := FakeDesFirePicc
  fake.key = key
  card := DesFireCard (IsoDepCard fake)
  expect-not card.is-authenticated
  card.authenticate-iso --key-number=0 --key=key
  expect card.is-authenticated

test-authenticate-iso-fails-with-wrong-key:
  key := ByteArray 24: it
  wrong-key := ByteArray 24: 0xFF
  fake := FakeDesFirePicc
  fake.key = key
  card := DesFireCard (IsoDepCard fake)
  exception := catch: card.authenticate-iso --key-number=0 --key=wrong-key
  expect-equals DesFireException.AUTHENTICATION-ERROR exception.status

test-authenticate-aes-succeeds:
  key := ByteArray 16: it
  fake := FakeDesFirePicc
  fake.key = key
  card := DesFireCard (IsoDepCard fake)
  expect-not card.is-authenticated
  card.authenticate-aes --key-number=0 --key=key
  expect card.is-authenticated

test-authenticate-aes-fails-with-wrong-key:
  key := ByteArray 16: it
  wrong-key := ByteArray 16: 0xFF
  fake := FakeDesFirePicc
  fake.key = key
  card := DesFireCard (IsoDepCard fake)
  exception := catch: card.authenticate-aes --key-number=0 --key=wrong-key
  expect-equals DesFireException.AUTHENTICATION-ERROR exception.status

/**
A single-block cipher primitive for the fake's own authentication
  handshake, mirroring $DesFireCard's own (private, so not importable
  here) `SessionCipher_` abstraction -- needed since the fake has to
  independently play both DES/3DES's 8-byte-block authentication
  schemes and AES's 16-byte-block one.
*/
interface FakeSessionCipher_:
  block-size -> int
  encrypt-block block/ByteArray -> ByteArray
  decrypt-block block/ByteArray -> ByteArray

class FakeDesFamilyCipher_ implements FakeSessionCipher_:
  cipher_/BlockCipher
  constructor .cipher_:
  block-size -> int: return 8
  encrypt-block block/ByteArray -> ByteArray: return cipher_.encrypt block
  decrypt-block block/ByteArray -> ByteArray: return cipher_.decrypt block

class FakeAesCipher_ implements FakeSessionCipher_:
  key_/ByteArray
  constructor .key_:
  block-size -> int: return 16
  encrypt-block block/ByteArray -> ByteArray:
    encryptor := AesEcb.encryptor key_
    try:
      return encryptor.encrypt block
    finally:
      encryptor.close
  decrypt-block block/ByteArray -> ByteArray:
    decryptor := AesEcb.decryptor key_
    try:
      return decryptor.decrypt block
    finally:
      decryptor.close

fake-cbc-encrypt_ cipher/FakeSessionCipher_ data/ByteArray --iv/ByteArray -> ByteArray:
  block-size := cipher.block-size
  result := ByteArray data.size
  previous := iv
  for i := 0; i < data.size; i += block-size:
    plain := data[i .. i + block-size]
    xored := ByteArray block-size: plain[it] ^ previous[it]
    encrypted := cipher.encrypt-block xored
    result.replace i encrypted
    previous = encrypted
  return result

fake-cbc-decrypt_ cipher/FakeSessionCipher_ data/ByteArray --iv/ByteArray -> ByteArray:
  block-size := cipher.block-size
  result := ByteArray data.size
  previous := iv
  for i := 0; i < data.size; i += block-size:
    ciphertext := data[i .. i + block-size]
    decrypted := cipher.decrypt-block ciphertext
    plain := ByteArray block-size: decrypted[it] ^ previous[it]
    result.replace i plain
    previous = ciphertext
  return result

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
  auth-nonce-size_/int := 8
  auth-fake-cipher_/FakeSessionCipher_? := null
  session-key_/BlockCipher? := null

  uid -> ByteArray: return #[0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
  type -> int: return 0
  close -> none:

  transceive bytes/ByteArray --check-crc/bool=false -> ByteArray?:
    // FSCI=8 (FSC=256): large enough that even AES authentication's
    // 32-byte step2 message fits in one I-block, so this fake doesn't
    // need to implement incoming chaining reassembly.
    if bytes.size == 2 and bytes[0] == 0xE0: return #[0x02, 0x08]

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
    if code == 0x0A: return authenticate-step1_ data --nonce-size=8
    if code == 0x1A: return authenticate-step1_ data --nonce-size=8
    if code == 0xAA: return authenticate-step1_ data --nonce-size=16
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
      raw := file["data"][offset .. offset + size]
      return (protect_ raw --communication-settings=file["communication-settings"]) + #[0x00]
    if code == 0x3D:
      file-id := data[0]
      file := files_.get file-id
      if not file: return #[0xF0]
      offset := data[1] | (data[2] << 8) | (data[3] << 16)
      size := data[4] | (data[5] << 8) | (data[6] << 16)
      payload := data[7 ..]
      plain := unprotect_ payload --communication-settings=file["communication-settings"] --plain-size=size
      stored := file["data"]
      stored.replace offset plain
      return #[0x00]
    throw "Unhandled native command in fake: 0x$(%02x code)"

  /** Mirrors $DesFireCard's own MACing/enciphering, independently, for outgoing (PICC-to-PCD) data. */
  protect_ data/ByteArray --communication-settings/int -> ByteArray:
    if communication-settings == 0x01: return data + (mac_ data) // MACed.
    if communication-settings == 0x03: // Enciphered.
      crc := crc-a data
      with-crc := data + #[crc & 0xFF, (crc >> 8) & 0xFF]
      padded := with-crc + (ByteArray (round-up_ with-crc.size 8) - with-crc.size)
      return cbc-encrypt session-key_ padded
    return data // Plain.

  /** Mirrors $DesFireCard's own MAC/encryption checking, independently, for incoming (PCD-to-PICC) data. */
  unprotect_ payload/ByteArray --communication-settings/int --plain-size/int -> ByteArray:
    if communication-settings == 0x01: // MACed.
      plain := payload[.. plain-size]
      received-mac := payload[plain-size ..]
      if received-mac != (mac_ plain): throw "FAKE_MAC_MISMATCH"
      return plain
    if communication-settings == 0x03: // Enciphered.
      decrypted := cbc-decrypt session-key_ payload
      plain := decrypted[.. plain-size]
      crc := crc-a plain
      if decrypted[plain-size] != crc & 0xFF or decrypted[plain-size + 1] != (crc >> 8) & 0xFF:
        throw "FAKE_CRC_MISMATCH"
      return plain
    return payload[.. plain-size] // Plain.

  mac_ data/ByteArray -> ByteArray:
    padded := data + (ByteArray (round-up_ data.size 8) - data.size)
    encrypted := cbc-encrypt session-key_ padded
    return encrypted[encrypted.size - 8 .. encrypted.size - 4]

  round-up_ value/int multiple/int -> int:
    remainder := value % multiple
    if remainder == 0: return value
    return value + multiple - remainder

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

  authenticate-step1_ data/ByteArray --nonce-size/int -> ByteArray:
    auth-nonce-size_ = nonce-size
    auth-fake-cipher_ = nonce-size == 16 ? (FakeAesCipher_ key) : (FakeDesFamilyCipher_ (key.size == 8 ? (Des --key=key) : (TripleDes --key=key)))
    rnd-b_ = ByteArray nonce-size: random 0x100
    encrypted-rnd-b_ = fake-cbc-encrypt_ auth-fake-cipher_ rnd-b_ --iv=(ByteArray nonce-size)
    return encrypted-rnd-b_ + #[0xAF]

  authenticate-step2_ data/ByteArray -> ByteArray:
    nonce-size := auth-nonce-size_
    cipher := auth-fake-cipher_
    plain := fake-cbc-decrypt_ cipher data --iv=encrypted-rnd-b_
    rnd-a := plain[.. nonce-size]
    received-rnd-b-rotated := plain[nonce-size ..]
    expected-rnd-b-rotated := rnd-b_[1 ..] + rnd-b_[.. 1]
    if received-rnd-b-rotated != expected-rnd-b-rotated: return #[0xAE]

    rnd-a-rotated := rnd-a[1 ..] + rnd-a[.. 1]
    encrypted := fake-cbc-encrypt_ cipher rnd-a-rotated --iv=data[nonce-size .. nonce-size * 2]

    // Secure-messaging tests only exercise the legacy (8-byte nonce, 8/16
    // byte key) scheme, which is all this derives; ISO/AES sessions skip
    // it since nothing here round-trips MACed/Enciphered data through them.
    if nonce-size == 8 and (key.size == 8 or key.size == 16):
      session-key_ = key.size == 8
          ? (Des --key=(rnd-a[.. 4] + rnd-b_[.. 4]))
          : (TripleDes --key=(rnd-a[.. 4] + rnd-b_[.. 4] + rnd-a[4 ..] + rnd-b_[4 ..]))

    return encrypted + #[0x00]
