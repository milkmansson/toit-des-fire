// Copyright (C) 2026 Toit contributors.
// Use of this source code is governed by a Zero-Clause BSD license that can
// be found in the EXAMPLES_LICENSE file.

/**
Hardware test for $DesFireCard over a PN532 (I2C).

DESFire sits on $IsoDepCard, which only needs plain `Target.transceive`
  (no raw-frame access), so this all works over the PN532.

Steps, in order:

1. UID + $DesFireCard.get-version + $DesFireCard.get-application-ids
   (read-only, safe on any card).
2. $DesFireCard.authenticate with the commonly-cited factory-default
   PICC master key (8 zero bytes) -- this is a widely-published
   convention for a virgin card, not a guaranteed fact about *your*
   card; it will just fail cleanly (AUTHENTICATION_ERROR) if the key's
   been changed or isn't DES/2K3DES.
3. If step 2 succeeded, $RUN-WRITE-TESTS gates everything that
   actually changes card state: creates a scratch application and
   file, round-trips Plain/MACed/Enciphered $DesFireCard.write-data
   and $DesFireCard.read-data, then deletes what it created. Leave
   this false until you're sure you're not pointed at a card you care
   about.
4. $DesFireCard.authenticate-iso / $DesFireCard.authenticate-aes are
   only exercised if $ISO-KEY / $AES-KEY are set -- a virgin card's
   PICC master key is DES/2K3DES, so these need a card you've actually
   configured with those key types.
*/

import gpio
import i2c
import des-fire show DesFireCard DesFireException
import nfc.iso-dep show IsoDepCard
import pn53x show Pn53x

// I2C test harness (2026-11-07); keep in sync with
// toit-pn53x/examples/main.toit if the wiring changes. IRQ/RESET are
// both optional -- see that file's comment -- and unset here since
// only VCC/GND/SDA/SCL are wired so far.
SDA ::= 19
SCL ::= 20
IRQ-PIN/int? ::= null
RESET-PIN/int? ::= null

// Commonly-cited factory default for a virgin card's PICC master key
// -- not guaranteed for your card.
DEFAULT-KEY ::= ByteArray 8

// Set these only if you have a card configured with ISO 3K3DES (24
// bytes) or AES-128 (16 bytes) keys to test authenticate-iso/-aes.
ISO-KEY/ByteArray? := null
AES-KEY/ByteArray? := null

// Leave false until you're sure the card in the field is a scratch
// card, not one you care about -- true creates and deletes an
// application/file on it.
RUN-WRITE-TESTS := false

main:
  sda := gpio.Pin SDA
  scl := gpio.Pin SCL
  irq := IRQ-PIN and (gpio.Pin IRQ-PIN)
  reset := RESET-PIN and (gpio.Pin RESET-PIN)

  bus := i2c.Bus --sda=sda --scl=scl --frequency=100_000
  device := bus.device Pn53x.I2C-ADDRESS
  pn53x := Pn53x.i2c device --irq=irq --reset=reset

  pn53x.on
  print "Firmware: $pn53x.miscellaneous.firmware-version"
  print "Waiting for a DESFire card..."

  target := null
  while not target:
    target = pn53x.poll
    if not target: sleep --ms=200

  print "Found: $target"
  iso-dep := IsoDepCard target
  card := DesFireCard iso-dep
  print "UID: $iso-dep.uid"

  print "GetVersion: $card.get-version"
  print "Application IDs: $card.get-application-ids"

  print "Authenticating with the factory-default PICC master key..."
  authenticated := false
  exception := catch:
    card.authenticate --key-number=0 --key=DEFAULT-KEY
    authenticated = true
  if authenticated:
    print "PASS: legacy authenticate succeeded."
  else:
    print "Legacy authenticate failed: $exception (expected if the key's been changed)."

  if authenticated and RUN-WRITE-TESTS:
    run-write-tests_ card
  else if authenticated:
    print "Skipping write tests (RUN-WRITE-TESTS is false)."

  if ISO-KEY:
    print "Authenticating with authenticate-iso..."
    iso-exception := catch: card.authenticate-iso --key-number=0 --key=ISO-KEY
    print (iso-exception ? "FAIL: $iso-exception" : "PASS: ISO 3K3DES authenticate succeeded.")
  if AES-KEY:
    print "Authenticating with authenticate-aes..."
    aes-exception := catch: card.authenticate-aes --key-number=0 --key=AES-KEY
    print (aes-exception ? "FAIL: $aes-exception" : "PASS: AES authenticate succeeded.")

  pn53x.off
  device.close
  bus.close
  if irq: irq.close
  if reset: reset.close
  scl.close
  sda.close

run-write-tests_ card/DesFireCard -> none:
  aid := 0x00AABB
  print "Creating scratch application $(%06x aid)..."
  catch: card.delete-application aid // Clean up a previous failed run, if any.
  card.create-application aid --key-settings=0x0F --number-of-keys=1
  card.select-application aid
  card.authenticate --key-number=0 --key=DEFAULT-KEY

  file-id := 1
  card.create-standard-data-file file-id --size=16
  data := #[1, 2, 3, 4, 5, 6, 7, 8]

  card.write-data file-id data --communication-settings=DesFireCard.COMMUNICATION-PLAIN
  plain-back := card.read-data file-id --size=data.size --communication-settings=DesFireCard.COMMUNICATION-PLAIN
  print (plain-back == data ? "PASS: Plain round trip." : "FAIL: Plain round trip, got $plain-back.")

  card.write-data file-id data --communication-settings=DesFireCard.COMMUNICATION-MACED
  maced-back := card.read-data file-id --size=data.size --communication-settings=DesFireCard.COMMUNICATION-MACED
  print (maced-back == data ? "PASS: MACed round trip." : "FAIL: MACed round trip, got $maced-back.")

  card.write-data file-id data --communication-settings=DesFireCard.COMMUNICATION-ENCIPHERED
  enciphered-back := card.read-data file-id --size=data.size --communication-settings=DesFireCard.COMMUNICATION-ENCIPHERED
  print (enciphered-back == data ? "PASS: Enciphered round trip." : "FAIL: Enciphered round trip, got $enciphered-back.")

  print "Cleaning up scratch application..."
  card.select-application 0
  card.authenticate --key-number=0 --key=DEFAULT-KEY
  card.delete-application aid
