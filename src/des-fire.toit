// Copyright (C) 2026 Toit contributors.
// Use of this source code is governed by an MIT-style license that can be
// found in the LICENSE file.

import crypto.aes show AesEcb
import crypto.crc show crc-a
import des show Des TripleDes BlockCipher
import nfc.iso-dep show IsoDepCard

/**
MIFARE DESFire's native command set, on top of $IsoDepCard and
  `toit-des`.

Only "native" command framing is implemented (the command byte and its
  parameters go straight into the ISO-DEP APDU); ISO 7816-4-wrapped mode
  (where commands are sent as standard CLA/INS/P1/P2 APDUs) is not.

Three authentication schemes are implemented, all the same three-pass
  ISO/IEC 9798-2 mutual authentication structure (the same family as
  MIFARE Ultralight C's — see `toit-mifare-ultralight` — plus a
  session-key derivation step at the end): $DesFireCard.authenticate
  (command `0x0A`, legacy DES/2K3DES, an 8-byte nonce/block size),
  $DesFireCard.authenticate-iso (command `0x1A`, ISO 3K3DES, also an
  8-byte nonce/block size), and $DesFireCard.authenticate-aes (command
  `0xAA`, AES-128, a 16-byte nonce/block size).

$DesFireCard.read-data and $DesFireCard.write-data support DESFire's
  legacy MACed/Enciphered communication settings (a CBC-MAC — session
  key, zero IV — appended to outgoing data and checked on incoming
  data; or CBC encryption — session key, zero IV — with a trailing
  CRC16, in both directions). Only the data portion of a command is
  protected, matching DESFire's own split between a command's (plain)
  header and its (optionally protected) data. This is expressed
  generically over $SessionCipher_ so it runs with a session key from
  any of the three authentication methods above, not just DES/3DES's
  — but it's still the *legacy* MAC/encryption scheme specifically.
  DESFire EV1's own secure messaging under AES authentication actually
  uses AES-CMAC (not plain CBC-MAC) and its own enciphering convention;
  $DesFireCard.authenticate-aes's session key isn't paired with a
  matching CMAC-based implementation here, so treat
  $DesFireCard.read-data/$DesFireCard.write-data's protected modes as
  verified self-consistent for legacy/ISO sessions only.
*/

/**
A single-block cipher primitive, abstracting over $BlockCipher's 8-byte
  DES/3DES blocks ($DesFamilySessionCipher_) and AES's 16-byte blocks
  ($AesSessionCipher_), so authentication and secure messaging can
  share one CBC implementation ($cbc-encrypt_, $cbc-decrypt_) regardless
  of which scheme produced the session key.
*/
interface SessionCipher_:
  block-size -> int
  encrypt-block block/ByteArray -> ByteArray
  decrypt-block block/ByteArray -> ByteArray

class DesFamilySessionCipher_ implements SessionCipher_:
  cipher_/BlockCipher
  constructor .cipher_:
  block-size -> int: return 8
  encrypt-block block/ByteArray -> ByteArray: return cipher_.encrypt block
  decrypt-block block/ByteArray -> ByteArray: return cipher_.decrypt block

class AesSessionCipher_ implements SessionCipher_:
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

/** Encrypts $data (a multiple of $cipher's block size) with $cipher in CBC mode. */
cbc-encrypt_ cipher/SessionCipher_ data/ByteArray --iv/ByteArray -> ByteArray:
  block-size := cipher.block-size
  if data.size % block-size != 0: throw "INVALID_ARGUMENT"
  result := ByteArray data.size
  previous := iv
  for i := 0; i < data.size; i += block-size:
    plain := data[i .. i + block-size]
    xored := ByteArray block-size: plain[it] ^ previous[it]
    encrypted := cipher.encrypt-block xored
    result.replace i encrypted
    previous = encrypted
  return result

/** Decrypts $data (a multiple of $cipher's block size) with $cipher in CBC mode. See $cbc-encrypt_. */
cbc-decrypt_ cipher/SessionCipher_ data/ByteArray --iv/ByteArray -> ByteArray:
  block-size := cipher.block-size
  if data.size % block-size != 0: throw "INVALID_ARGUMENT"
  result := ByteArray data.size
  previous := iv
  for i := 0; i < data.size; i += block-size:
    ciphertext := data[i .. i + block-size]
    decrypted := cipher.decrypt-block ciphertext
    plain := ByteArray block-size: decrypted[it] ^ previous[it]
    result.replace i plain
    previous = ciphertext
  return result

class DesFireCard:
  static ADDITIONAL-FRAME_ ::= 0xAF
  static OPERATION-OK_ ::= 0x00

  /** No MAC or encryption; see $read-data and $write-data. */
  static COMMUNICATION-PLAIN ::= 0x00
  /** A 4-byte CBC-MAC is appended to the data; see $read-data and $write-data. */
  static COMMUNICATION-MACED ::= 0x01
  /** The data is CBC-encrypted with a trailing CRC16; see $read-data and $write-data. */
  static COMMUNICATION-ENCIPHERED ::= 0x03

  static GET-VERSION_ ::= 0x60
  static GET-APPLICATION-IDS_ ::= 0x6A
  static SELECT-APPLICATION_ ::= 0x5A
  static CREATE-APPLICATION_ ::= 0xCA
  static DELETE-APPLICATION_ ::= 0xDA
  static FORMAT-PICC_ ::= 0xFC
  static FREE-MEMORY_ ::= 0x6E
  static AUTHENTICATE-LEGACY_ ::= 0x0A
  static AUTHENTICATE-ISO_ ::= 0x1A
  static AUTHENTICATE-AES_ ::= 0xAA
  static GET-FILE-IDS_ ::= 0x6F
  static GET-FILE-SETTINGS_ ::= 0xF5
  static CREATE-STD-DATA-FILE_ ::= 0xCD
  static DELETE-FILE_ ::= 0xDF
  static READ-DATA_ ::= 0xBD
  static WRITE-DATA_ ::= 0x3D

  target_/IsoDepCard
  session-key_/SessionCipher_? := null

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

  $communication-settings must match the file's own setting (see
    $create-standard-data-file and $get-file-settings); it determines
    whether the response's data is protected by a MAC or encryption
    that needs to be checked/removed, both of which need a current
    session key (see $authenticate).
  */
  read-data file-id/int --offset/int=0 --size/int --communication-settings/int=COMMUNICATION-PLAIN -> ByteArray:
    bytes := #[
      file-id,
      offset & 0xFF, (offset >> 8) & 0xFF, (offset >> 16) & 0xFF,
      size & 0xFF, (size >> 8) & 0xFF, (size >> 16) & 0xFF,
    ]
    response := command_ READ-DATA_ bytes
    if communication-settings == COMMUNICATION-PLAIN: return response
    if communication-settings == COMMUNICATION-MACED: return unmac-response_ response
    if communication-settings == COMMUNICATION-ENCIPHERED: return decrypt-response_ response --plain-size=size
    throw "INVALID_ARGUMENT"

  /** Writes $data at $offset to $file-id. See $read-data for $communication-settings. */
  write-data file-id/int data/ByteArray --offset/int=0 --communication-settings/int=COMMUNICATION-PLAIN -> none:
    size := data.size
    header := #[
      file-id,
      offset & 0xFF, (offset >> 8) & 0xFF, (offset >> 16) & 0xFF,
      size & 0xFF, (size >> 8) & 0xFF, (size >> 16) & 0xFF,
    ]
    protected-data := data
    if communication-settings == COMMUNICATION-MACED:
      protected-data = data + (mac_ data)
    else if communication-settings == COMMUNICATION-ENCIPHERED:
      protected-data = encrypt-data_ data
    else if communication-settings != COMMUNICATION-PLAIN:
      throw "INVALID_ARGUMENT"
    command_ WRITE-DATA_ (header + protected-data)

  /** Computes the CBC-MAC (session key, zero IV) over $data, truncated to 4 bytes. */
  mac_ data/ByteArray -> ByteArray:
    if not session-key_: throw "DESFIRE_NOT_AUTHENTICATED"
    block-size := session-key_.block-size
    padded := data + (ByteArray (round-up_ data.size block-size) - data.size)
    encrypted := cbc-encrypt_ session-key_ padded --iv=(ByteArray block-size)
    return encrypted[encrypted.size - block-size .. encrypted.size - block-size + 4]

  /** Checks and strips the trailing 4-byte CBC-MAC from a $response. */
  unmac-response_ response/ByteArray -> ByteArray:
    if response.size < 4: throw "DESFIRE_AUTH_FAILED"
    data := response[.. response.size - 4]
    received-mac := response[response.size - 4 ..]
    if received-mac != (mac_ data): throw "DESFIRE_AUTH_FAILED"
    return data

  /** Encrypts $data (session key, zero IV), appending a CRC16 and zero-padding to a multiple of the session cipher's block size first. */
  encrypt-data_ data/ByteArray -> ByteArray:
    if not session-key_: throw "DESFIRE_NOT_AUTHENTICATED"
    crc := crc-a data
    with-crc := data + #[crc & 0xFF, (crc >> 8) & 0xFF]
    padded := with-crc + (ByteArray (round-up_ with-crc.size session-key_.block-size) - with-crc.size)
    return cbc-encrypt_ session-key_ padded --iv=(ByteArray session-key_.block-size)

  /** Decrypts an Enciphered $response (session key, zero IV), checking the trailing CRC16 and returning the $plain-size data bytes. */
  decrypt-response_ response/ByteArray --plain-size/int -> ByteArray:
    if not session-key_: throw "DESFIRE_NOT_AUTHENTICATED"
    decrypted := cbc-decrypt_ session-key_ response --iv=(ByteArray session-key_.block-size)
    if decrypted.size < plain-size + 2: throw "DESFIRE_AUTH_FAILED"
    data := decrypted[.. plain-size]
    crc := crc-a data
    if decrypted[plain-size] != crc & 0xFF or decrypted[plain-size + 1] != (crc >> 8) & 0xFF:
      throw "DESFIRE_AUTH_FAILED"
    return data

  static round-up_ value/int multiple/int -> int:
    remainder := value % multiple
    if remainder == 0: return value
    return value + multiple - remainder

  /**
  Authenticates with $key-number using DESFire's legacy DES/2K3DES
    scheme. See this class's doc comment for the shared three-pass
    structure, and $read-data/$write-data for what the resulting
    session key enables.

  $key must be 8 bytes (single DES) or 16 bytes (2-key 3DES).
  */
  authenticate --key-number/int --key/ByteArray -> none:
    if key.size != 8 and key.size != 16: throw "INVALID_ARGUMENT"
    block-cipher/BlockCipher := key.size == 8 ? (Des --key=key) : (TripleDes --key=key)
    session-key_ = authenticate-generic_ AUTHENTICATE-LEGACY_ key-number (DesFamilySessionCipher_ block-cipher)
        --derive-session-key=:: | rnd-a/ByteArray rnd-b/ByteArray |
          DesFamilySessionCipher_ (key.size == 8
              ? (Des --key=(rnd-a[.. 4] + rnd-b[.. 4]))
              : (TripleDes --key=(rnd-a[.. 4] + rnd-b[.. 4] + rnd-a[4 ..] + rnd-b[4 ..])))

  /**
  Authenticates with $key-number using DESFire's ISO authentication
    scheme (3-key 3DES, also known as 3K3DES). See this class's doc
    comment for the shared three-pass structure, and
    $read-data/$write-data for what the resulting session key enables.

  $key must be 24 bytes.
  */
  authenticate-iso --key-number/int --key/ByteArray -> none:
    if key.size != 24: throw "INVALID_ARGUMENT"
    session-key_ = authenticate-generic_ AUTHENTICATE-ISO_ key-number (DesFamilySessionCipher_ (TripleDes --key=key))
        --derive-session-key=:: | rnd-a/ByteArray rnd-b/ByteArray |
          key-material := rnd-a[.. 4] + rnd-b[.. 4] + rnd-a[.. 4] + rnd-b[.. 4] + rnd-a[4 ..] + rnd-b[4 ..]
          DesFamilySessionCipher_ (TripleDes --key=key-material)

  /**
  Authenticates with $key-number using DESFire EV1's AES authentication
    scheme. See this class's doc comment for the shared three-pass
    structure (here with a 16-byte AES block as the nonce/block size,
    rather than DES/3DES's 8 bytes), and $read-data/$write-data for
    what the resulting session key enables.

  $key must be 16 bytes (AES-128).
  */
  authenticate-aes --key-number/int --key/ByteArray -> none:
    if key.size != 16: throw "INVALID_ARGUMENT"
    session-key_ = authenticate-generic_ AUTHENTICATE-AES_ key-number (AesSessionCipher_ key)
        --derive-session-key=:: | rnd-a/ByteArray rnd-b/ByteArray |
          AesSessionCipher_ (rnd-a[.. 4] + rnd-b[.. 4] + rnd-a[12 ..] + rnd-b[12 ..])

  /**
  Runs the three-pass mutual-authentication handshake shared by
    $authenticate, $authenticate-iso, and $authenticate-aes: the PICC
    sends an encrypted nonce (RndB); the PCD decrypts it, generates its
    own nonce (RndA), and replies with RndA followed by a rotated RndB,
    both encrypted, chained from the PICC's own ciphertext; the PICC
    replies with a rotated, re-encrypted RndA, which the PCD checks
    against its own RndA to confirm the PICC also holds the key.

  $derive-session-key computes the resulting session key from the two
    nonces, since the derivation formula differs per scheme.
  */
  authenticate-generic_ command/int key-number/int cipher/SessionCipher_ --derive-session-key/Lambda -> SessionCipher_:
    nonce-size := cipher.block-size

    step1 := unwrap-single-frame_ (target_.transceive #[command, key-number]) --expect-status=ADDITIONAL-FRAME_
    if step1.size != nonce-size: throw "DESFIRE_AUTH_FAILED"
    encrypted-rnd-b := step1
    rnd-b := cbc-decrypt_ cipher encrypted-rnd-b --iv=(ByteArray nonce-size)

    rnd-a := ByteArray nonce-size: random 0x100
    rnd-b-rotated := rnd-b[1 ..] + rnd-b[.. 1]
    plain := rnd-a + rnd-b-rotated
    encrypted := cbc-encrypt_ cipher plain --iv=encrypted-rnd-b

    step2 := unwrap-single-frame_ (target_.transceive (#[ADDITIONAL-FRAME_] + encrypted)) --expect-status=OPERATION-OK_
    if step2.size != nonce-size: throw "DESFIRE_AUTH_FAILED"

    rnd-a-rotated := cbc-decrypt_ cipher step2 --iv=encrypted[encrypted.size - nonce-size ..]
    expected-rnd-a-rotated := rnd-a[1 ..] + rnd-a[.. 1]
    if rnd-a-rotated != expected-rnd-a-rotated: throw "DESFIRE_AUTH_FAILED"

    return derive-session-key.call rnd-a rnd-b

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
