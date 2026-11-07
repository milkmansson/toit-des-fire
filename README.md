# MIFARE DESFire

MIFARE DESFire's native command set, on top of
[toit-nfc](https://github.com/milkmansson/toit-nfc)'s `IsoDepCard`
(ISO/IEC 14443-4 transport) and [toit-des](https://github.com/milkmansson/toit-des)
(the cipher DESFire's older authentication schemes and this package's
own name both come from).

## Scope

This covers DESFire's **native** command framing (the command byte and
parameters go straight into the ISO-DEP exchange) and three
authentication schemes: legacy **DES/2K3DES** (command `0x0A`, the
default cipher for a fresh card's PICC master key, and the scheme
EV0-era cards and basic EV1 use are built around), **ISO 3K3DES**
(command `0x1A`), and **AES-128** (command `0xAA`, EV1-and-up). All
three share the same three-pass challenge-response structure; see
`src/des-fire.toit`'s class doc comment. Deliberately not covered:

- **ISO 7816-4-wrapped command framing** (CLA/INS/P1/P2 APDUs) — native
  framing works for every DESFire generation, so there was no need for
  both.
- **AES-CMAC secure messaging.** `ReadData`/`WriteData`'s MACed/
  Enciphered communication settings (see below) implement the
  *legacy* CBC-MAC/CBC-encryption scheme only. They work with a
  session key from any of the three authentication methods (the
  implementation is block-size-agnostic), but DESFire EV1's own secure
  messaging under AES authentication actually uses AES-CMAC and its
  own enciphering convention, which isn't implemented — so treat
  `ReadData`/`WriteData`'s protected modes as applying to legacy/ISO
  sessions only.

## What's implemented

`GetVersion`, `GetApplicationIDs`, `SelectApplication`,
`CreateApplication`, `DeleteApplication`, `FormatPICC`, `GetFreeMemory`,
`Authenticate`/`authenticate-iso`/`authenticate-aes`, `GetFileIDs`,
`GetFileSettings`, `CreateStdDataFile`, `DeleteFile`, `ReadData`,
`WriteData`, and decoding for every documented native status byte
(`DesFireException`).

`ReadData`/`WriteData` support DESFire's legacy communication settings:
Plain, MACed (a 4-byte CBC-MAC appended to the data), and Enciphered
(the data CBC-encrypted with a trailing CRC16) — both using the
session key from whichever authentication method ran, with a zero IV
per command (legacy secure messaging doesn't chain the IV across
commands the way EV1-and-up's AES/ISO-3K3DES CommMode does; see
"Scope" above for the AES-CMAC caveat).

## On confidence

The authentication handshake (the three-pass RndA/RndB exchange with
CBC chaining and nonce rotation) is the same structure as MIFARE
Ultralight C's — see
[toit-mifare-ultralight](https://github.com/milkmansson/toit-mifare-ultralight#status)
— and is checked the same way: by simulating the full PICC side of the
exchange with real shared-key crypto, including a wrong-key case, for
all three authentication schemes (they share one implementation —
`DesFireCard.authenticate-generic_` — parameterized by command byte,
cipher, and nonce/block size, so this is one code path tested three
ways, not three separate ones).

**Session-key derivation formulas** are one piece those checks alone
can't fully confirm. For legacy 2K3DES (`RndA[0:4] + RndB[0:4] +
RndA[4:8] + RndB[4:8]`): while researching it, found one source
directly describing this formula and other sources disputing it
without a clear resolution either way. For AES (`RndA[0:4] + RndB[0:4]
+ RndA[12:16] + RndB[12:16]`): this is the commonly-cited formula
across several independent DESFire library implementations, giving
reasonable confidence, but still unverified against a real card. For
ISO 3K3DES: genuinely uncertain — an 8-byte RndA/RndB pair doesn't
contain enough distinct material to produce a 24-byte key without some
repetition, and which 8-byte chunk gets repeated (this implementation
repeats `RndA[0:4] + RndB[0:4]` as the third key segment) is a guess,
not a sourced formula. The secure-messaging tests exercise the legacy
formula indirectly (the fake PICC derives the same session key
independently and uses it for its own MAC/encryption checks, so a
wrong formula on either side would break the round trip), but that
only proves self-consistency, not that it matches what a real DESFire
chip does. The AES/ISO session-key formulas aren't exercised this way
at all (see "Scope" above for why AES's session key isn't used for
secure messaging here) — only the authentication handshake itself is
tested for those two.

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
