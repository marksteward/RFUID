What
====

A Python library to identify an RFID card (reasonably) uniquely.
Also happens to implement the ACR122 API, and exposes some PN532 functionality.

Why
===

Some new Paywave cards all return the same NFCID1, and UK Passports randomise their IDs.

What's missing
==============

Error checking

Examples
========

See the "main" part of each script for now.

Prerequisites
=============

On Debian:
```
 sudo apt-get install python-pyscard pcscd pcsc-tools
 sudo wget http://ludovic.rousseau.free.fr/softwares/pcsc-tools/smartcard_list.txt -O /usr/share/pcsc/smartcard_list.txt
```

On some versions of Debian, edit:

```
 /usr/lib/pcsc/drivers/ifd-ccid.bundle/Contents/Info.plist
```

changing ifdDriverOptions from 0x0000 to 0x0004.

```
 sudo service pcscd restart

 pcsc_scan
```

