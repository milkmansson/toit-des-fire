// Copyright (C) 2026 Toit contributors.
// Use of this source code is governed by an MIT-style license that can be
// found in the LICENSE file.

import des show Des TripleDes BlockCipher cbc-encrypt cbc-decrypt
import nfc.iso-dep show IsoDepCard

/**
MIFARE DESFire's legacy DES/3DES native command set, on top of
  $IsoDepCard and `toit-des`.

Only "native" command framing is implemented (the command byte and its
  parameters go straight into the ISO-DEP APDU); ISO 7816-4-wrapped mode
  (where commands are sent as standard CLA/INS/P1/P2 APDUs) is not.

Only the legacy DES/2K3DES authentication scheme (command 0x0A) is
  implemented, not AES authentication (0xAA) or the separate ISO/3K3DES
  scheme (0x1A) — both of those are later/alternative schemes DESFire
  EV1 and up also support, not needed for EV0-era cards or basic EV1
  use with the PICC master key's default cipher.

Secure messaging — using the session key $authenticate derives to MAC
  or encrypt subsequent commands (DESFire's "MACed"/"Enciphered"
  communication settings) — is not implemented. $read-data and
  $write-data only work against files configured for "Plain"
  communication, which don't need it.
*/
class DesFireCard:
  static ADDITIONAL-FRAME_ ::= 0xAF
  static OPERATION-OK_ ::= 0x00

  static GET-VERSION_ ::= 0x60
  static GET-APPLICATION-IDS_ ::= 0x6A
  static SELECT-APPLICATION_ ::= 0x5A
  static CREATE-APPLICATION_ ::= 0xCA
  static DELETE-APPLICATION_ ::= 0xDA
  static FORMAT-PICC_ ::= 0xFC
  static FREE-MEMORY_ ::= 0x6E
  static AUTHENTICATE-LEGACY_ ::= 0x0A
  static GET-FILE-IDS_ ::= 0x6F
  static GET-FILE-SETTINGS_ ::= 0xF5
  static CREATE-STD-DATA-FILE_ ::= 0xCD
  static DELETE-FILE_ ::= 0xDF
  static READ-DATA_ ::= 0xBD
  static WRITE-DATA_ ::= 0x3D

  target_/IsoDepCard
  session-key_/BlockCipher? := null

  constructor .target_:

  /** Whether a session key is active; see $authenticate. */
  is-authenticated -> bool: return session-key_ != null

  /** Drops the current session key, if any. */
  deauthenticate -> none: session-key_ = null

  /** The raw GetVersion response: hardware info, software info, and UID/batch/production-date info, concatenated. */
  get-version -> ByteArray: return command_ GET-VERSION_

  /** The AIDs (3-byte application IDs) of every application on the card. */
  get-application-ids -> List:
    data := command_ GET-APPLICATION-IDS_
    aids := []
    for i := 0; i < data.size; i += 3:
      aids.add (data[i] | (data[i + 1] << 8) | (data[i + 2] << 16))
    return aids

  /** Selects the application with the given 3-byte $aid (0 selects the PICC master application). */
  select-application aid/int -> none:
    bytes := #[aid & 0xFF, (aid >> 8) & 0xFF, (aid >> 16) & 0xFF]
    command_ SELECT-APPLICATION_ bytes
    // Any session key was for the previously selected application.
    session-key_ = null

  /** Creates an application with the given 3-byte $aid. $key-settings and $number-of-keys follow DESFire's own encoding; see the datasheet. */
  create-application aid/int --key-settings/int --number-of-keys/int -> none:
    bytes := #[aid & 0xFF, (aid >> 8) & 0xFF, (aid >> 16) & 0xFF, key-settings, number-of-keys]
    command_ CREATE-APPLICATION_ bytes

  /** Deletes the application with the given 3-byte $aid. */
  delete-application aid/int -> none:
    bytes := #[aid & 0xFF, (aid >> 8) & 0xFF, (aid >> 16) & 0xFF]
    command_ DELETE-APPLICATION_ bytes

  /** Erases the entire PICC, including all applications. Requires prior authentication with the PICC master key. */
  format-picc -> none: command_ FORMAT-PICC_

  /** The free EEPROM memory left on the card, in bytes. */
  free-memory -> int:
    data := command_ FREE-MEMORY_
    return data[0] | (data[1] << 8) | (data[2] << 16)

  /** The file IDs defined in the currently selected application. */
  get-file-ids -> List:
    data := command_ GET-FILE-IDS_
    ids := []
    data.do: ids.add it
    return ids

  /** The settings of the given $file-id in the currently selected application. */
  get-file-settings file-id/int -> DesFireFileSettings:
    return DesFireFileSettings.from-bytes (command_ GET-FILE-SETTINGS_ #[file-id])

  /**
  Creates a Standard Data File with the given $file-id, $size bytes.

  $communication-settings and $access-rights follow DESFire's own
    encoding (0x00 communication-settings is "Plain", which is what
    $read-data/$write-data support); see the datasheet.
  */
  create-standard-data-file file-id/int --size/int --communication-settings/int=0 --access-rights/int=0xEEEE -> none:
    bytes := #[
      file-id, communication-settings,
      access-rights & 0xFF, (access-rights >> 8) & 0xFF,
      size & 0xFF, (size >> 8) & 0xFF, (size >> 16) & 0xFF,
    ]
    command_ CREATE-STD-DATA-FILE_ bytes

  /** Deletes the given $file-id from the currently selected application. */
  delete-file file-id/int -> none:
    command_ DELETE-FILE_ #[file-id]

  /**
  Reads $size bytes starting at $offset from $file-id.

  Only works for a file whose communication settings are "Plain" (see
    $create-standard-data-file); this does not implement the
    MACed/enciphered communication secure messaging would need.
  */
  read-data file-id/int --offset/int=0 --size/int -> ByteArray:
    bytes := #[
      file-id,
      offset & 0xFF, (offset >> 8) & 0xFF, (offset >> 16) & 0xFF,
      size & 0xFF, (size >> 8) & 0xFF, (size >> 16) & 0xFF,
    ]
    return command_ READ-DATA_ bytes

  /** Writes $data at $offset to $file-id. See $read-data for the "Plain" communication-settings restriction. */
  write-data file-id/int data/ByteArray --offset/int=0 -> none:
    size := data.size
    header := #[
      file-id,
      offset & 0xFF, (offset >> 8) & 0xFF, (offset >> 16) & 0xFF,
      size & 0xFF, (size >> 8) & 0xFF, (size >> 16) & 0xFF,
    ]
    command_ WRITE-DATA_ (header + data)

  /**
  Authenticates with $key-number using DESFire's legacy DES/2K3DES
    scheme: an ISO/IEC 9798-2 three-pass mutual authentication, the same
    family as MIFARE Ultralight C's (see `toit-mifare-ultralight`), but
    with an added session-key derivation step at the end, since DESFire
    (unlike Ultralight C) uses the session key to protect later commands
    — once secure messaging is implemented; see this class's doc
    comment for what $authenticate itself does and doesn't enable yet.

  $key must be 8 bytes (single DES) or 16 bytes (2-key 3DES).
  */
  authenticate --key-number/int --key/ByteArray -> none:
    if key.size != 8 and key.size != 16: throw "INVALID_ARGUMENT"
    cipher/BlockCipher := key.size == 8 ? (Des --key=key) : (TripleDes --key=key)

    step1 := unwrap-single-frame_ (target_.transceive #[AUTHENTICATE-LEGACY_, key-number]) --expect-status=ADDITIONAL-FRAME_
    if step1.size != 8: throw "DESFIRE_AUTH_FAILED"
    encrypted-rnd-b := step1
    rnd-b := cbc-decrypt cipher encrypted-rnd-b

    rnd-a := ByteArray 8: random 0x100
    rnd-b-rotated := rnd-b[1 ..] + rnd-b[.. 1]
    plain := rnd-a + rnd-b-rotated
    encrypted := cbc-encrypt cipher plain --iv=encrypted-rnd-b

    step2 := unwrap-single-frame_ (target_.transceive (#[ADDITIONAL-FRAME_] + encrypted)) --expect-status=OPERATION-OK_
    if step2.size != 8: throw "DESFIRE_AUTH_FAILED"

    rnd-a-rotated := cbc-decrypt cipher step2 --iv=encrypted[8 .. 16]
    expected-rnd-a-rotated := rnd-a[1 ..] + rnd-a[.. 1]
    if rnd-a-rotated != expected-rnd-a-rotated: throw "DESFIRE_AUTH_FAILED"

    session-key_ = derive-session-key_ key.size rnd-a rnd-b

  static derive-session-key_ key-size/int rnd-a/ByteArray rnd-b/ByteArray -> BlockCipher:
    if key-size == 8:
      return Des --key=(rnd-a[.. 4] + rnd-b[.. 4])
    return TripleDes --key=(rnd-a[.. 4] + rnd-b[.. 4] + rnd-a[4 ..] + rnd-b[4 ..])

  unwrap-single-frame_ response/ByteArray? --expect-status/int -> ByteArray:
    if not response or response.is-empty: throw "DESFIRE_NO_RESPONSE"
    status := response[response.size - 1]
    if status != expect-status: throw (DesFireException status)
    return response[.. response.size - 1]

  /**
  Sends a native command, transparently following the additional-frame
    (0xAF) continuation mechanism a multi-frame response uses.
  */
  command_ code/int data/ByteArray=#[] -> ByteArray:
    response := target_.transceive (#[code] + data)
    result := #[]
    while true:
      if not response or response.is-empty: throw "DESFIRE_NO_RESPONSE"
      status := response[response.size - 1]
      result += response[.. response.size - 1]
      if status == OPERATION-OK_: return result
      if status != ADDITIONAL-FRAME_: throw (DesFireException status)
      response = target_.transceive #[ADDITIONAL-FRAME_]

/** The settings of one DESFire file, as returned by $DesFireCard.get-file-settings. */
class DesFireFileSettings:
  static TYPE-STANDARD-DATA ::= 0x00
  static TYPE-BACKUP-DATA ::= 0x01
  static TYPE-VALUE ::= 0x02
  static TYPE-LINEAR-RECORD ::= 0x03
  static TYPE-CYCLIC-RECORD ::= 0x04

  type/int
  communication-settings/int
  access-rights/int
  /** The file's size in bytes, for a standard or backup data file; null for other file types. */
  file-size/int?

  constructor.from-bytes bytes/ByteArray:
    type = bytes[0]
    communication-settings = bytes[1]
    access-rights = bytes[2] | (bytes[3] << 8)
    if type == TYPE-STANDARD-DATA or type == TYPE-BACKUP-DATA:
      file-size = bytes[4] | (bytes[5] << 8) | (bytes[6] << 16)
    else:
      file-size = null

  stringify -> string:
    return "DesFireFileSettings(type=$type, communication-settings=$communication-settings, "
        + "access-rights=0x$(%04x access-rights), file-size=$file-size)"

/** A DESFire native command's non-OK status byte, decoded. */
class DesFireException:
  static NO-CHANGES ::= 0x0C
  static OUT-OF-EEPROM-ERROR ::= 0x0E
  static ILLEGAL-COMMAND-CODE ::= 0x1C
  static INTEGRITY-ERROR ::= 0x1E
  static NO-SUCH-KEY ::= 0x40
  static LENGTH-ERROR ::= 0x7E
  static PERMISSION-DENIED ::= 0x9D
  static PARAMETER-ERROR ::= 0x9E
  static APPLICATION-NOT-FOUND ::= 0xA0
  static APPL-INTEGRITY-ERROR ::= 0xA1
  static AUTHENTICATION-ERROR ::= 0xAE
  static BOUNDARY-ERROR ::= 0xBE
  static PICC-INTEGRITY-ERROR ::= 0xC1
  static COMMAND-ABORTED ::= 0xCA
  static PICC-DISABLED-ERROR ::= 0xCD
  static COUNT-ERROR ::= 0xCE
  static DUPLICATE-ERROR ::= 0xDE
  static EEPROM-ERROR ::= 0xEE
  static FILE-NOT-FOUND ::= 0xF0
  static FILE-INTEGRITY-ERROR ::= 0xF1

  static NAMES_ ::= {
    NO-CHANGES: "NO_CHANGES",
    OUT-OF-EEPROM-ERROR: "OUT_OF_EEPROM_ERROR",
    ILLEGAL-COMMAND-CODE: "ILLEGAL_COMMAND_CODE",
    INTEGRITY-ERROR: "INTEGRITY_ERROR",
    NO-SUCH-KEY: "NO_SUCH_KEY",
    LENGTH-ERROR: "LENGTH_ERROR",
    PERMISSION-DENIED: "PERMISSION_DENIED",
    PARAMETER-ERROR: "PARAMETER_ERROR",
    APPLICATION-NOT-FOUND: "APPLICATION_NOT_FOUND",
    APPL-INTEGRITY-ERROR: "APPL_INTEGRITY_ERROR",
    AUTHENTICATION-ERROR: "AUTHENTICATION_ERROR",
    BOUNDARY-ERROR: "BOUNDARY_ERROR",
    PICC-INTEGRITY-ERROR: "PICC_INTEGRITY_ERROR",
    COMMAND-ABORTED: "COMMAND_ABORTED",
    PICC-DISABLED-ERROR: "PICC_DISABLED_ERROR",
    COUNT-ERROR: "COUNT_ERROR",
    DUPLICATE-ERROR: "DUPLICATE_ERROR",
    EEPROM-ERROR: "EEPROM_ERROR",
    FILE-NOT-FOUND: "FILE_NOT_FOUND",
    FILE-INTEGRITY-ERROR: "FILE_INTEGRITY_ERROR",
  }

  status/int

  constructor .status:

  stringify -> string:
    name := NAMES_.get status --if-absent=(: "UNKNOWN")
    return "DesFireException($name, status=0x$(%02x status))"
