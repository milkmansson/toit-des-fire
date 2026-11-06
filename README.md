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
- **Secure messaging.** `authenticate` runs the full mutual-authentication
  handshake and derives a session key, but nothing in this package uses
  that key yet to MAC or encrypt subsequent commands (DESFire's "MACed"/
  "Enciphered" communication settings). `read-data`/`write-data` only
  work against files configured for "Plain" communication, which don't
  need it. This is the natural next piece to build on top of what's
  here.

## What's implemented

`GetVersion`, `GetApplicationIDs`, `SelectApplication`,
`CreateApplication`, `DeleteApplication`, `FormatPICC`, `GetFreeMemory`,
the legacy `Authenticate`, `GetFileIDs`, `GetFileSettings`,
`CreateStdDataFile`, `DeleteFile`, `ReadData`, `WriteData`, and decoding
for every documented native status byte (`DesFireException`).

## On confidence

The authentication handshake (the three-pass RndA/RndB exchange with
CBC chaining and nonce rotation) is the same structure as MIFARE
Ultralight C's — see
[toit-mifare-ultralight](https://github.com/milkmansson/toit-mifare-ultralight#status)
— and is checked the same way: by simulating the full PICC side of the
exchange with real shared-key crypto, including a wrong-key case. The
one piece that check can't reach is the **session-key derivation
formula** (`RndA[0:4] + RndB[0:4] + RndA[4:8] + RndB[4:8]` for a 2K3DES
key): while researching it, found one source directly describing this
formula and other sources disputing it without a clear resolution either
way, and since nothing in this package consumes the derived session key
yet (see "Secure messaging" above), there's no way to test it against an
independent oracle right now. This is the first thing to verify once
secure messaging is built and there's a real card to test the whole
chain against.

The native command set's exact command/status byte values are from
widely-published reference tables (shared across many independent
MIFARE DESFire libraries), not from NXP's own datasheet directly, and
none of this has been run against a real DESFire card.

---

Parts of this repository were developed with the help of [Claude Code](https://claude.com/claude-code).
