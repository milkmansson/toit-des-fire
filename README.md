# MIFARE DESFire

MIFARE DESFire's legacy DES/3DES native command set, on top of
[toit-nfc](https://github.com/milkmansson/toit-nfc)'s `IsoDepCard`
(ISO/IEC 14443-4 transport) and [toit-des](https://github.com/milkmansson/toit-des)
(the cipher DESFire's older authentication scheme and this package's
own name both come from).

## Scope

This covers DESFire's **native** command framing (the command byte and
parameters go straight into the ISO-DEP exchange) and its **legacy**
DES/2K3DES authentication (command `0x0A`) — the default cipher for a
fresh card's PICC master key, and the scheme EV0-era cards and basic EV1
use are built around. Deliberately not covered, all later/alternative
schemes DESFire also supports:

- **ISO 7816-4-wrapped command framing** (CLA/INS/P1/P2 APDUs) — native
  framing works for every DESFire generation, so there was no need for
  both.
- **AES authentication** (`0xAA`) and the separate ISO/3K3DES scheme
  (`0x1A`) — EV1-and-up alternatives to the legacy scheme this package
  implements.

## What's implemented

`GetVersion`, `GetApplicationIDs`, `SelectApplication`,
`CreateApplication`, `DeleteApplication`, `FormatPICC`, `GetFreeMemory`,
the legacy `Authenticate`, `GetFileIDs`, `GetFileSettings`,
`CreateStdDataFile`, `DeleteFile`, `ReadData`, `WriteData`, and decoding
for every documented native status byte (`DesFireException`).

`ReadData`/`WriteData` support all three legacy communication settings
a file can be configured with: Plain, MACed (a 4-byte CBC-MAC appended
to the data), and Enciphered (the data CBC-encrypted with a trailing
CRC16) — both using the session key `authenticate` derives, with a zero
IV per command (legacy DES/2K3DES secure messaging doesn't chain the IV
across commands the way EV1-and-up's AES/ISO-3K3DES CommMode does).

## On confidence

The authentication handshake (the three-pass RndA/RndB exchange with
CBC chaining and nonce rotation) is the same structure as MIFARE
Ultralight C's — see
[toit-mifare-ultralight](https://github.com/milkmansson/toit-mifare-ultralight#status)
— and is checked the same way: by simulating the full PICC side of the
exchange with real shared-key crypto, including a wrong-key case. The
**session-key derivation formula** (`RndA[0:4] + RndB[0:4] + RndA[4:8] +
RndB[4:8]` for a 2K3DES key) is one piece that check alone can't fully
confirm: while researching it, found one source directly describing
this formula and other sources disputing it without a clear resolution
either way. The secure-messaging tests now exercise it indirectly (the
fake PICC derives the same session key independently and uses it for
its own MAC/encryption checks, so a wrong formula on either side would
break the round trip), but that only proves self-consistency, not that
it matches what a real DESFire chip does.

Secure messaging's own wire format (MAC and encrypted-data layout,
zero-padding, CRC16 scope) is implemented and self-consistency-checked
the same way — the fake PICC performs the same MACing/enciphering
independently rather than just echoing bytes back — but, like the
session-key formula above, this doesn't confirm it matches a real
card's exact byte-for-byte behavior.

The native command set's exact command/status byte values are from
widely-published reference tables (shared across many independent
MIFARE DESFire libraries), not from NXP's own datasheet directly, and
none of this has been run against a real DESFire card.

---

Parts of this repository were developed with the help of [Claude Code](https://claude.com/claude-code).
