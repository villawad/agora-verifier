agora-verifier
==============


agora-verifier performs tally and cryptographic verification of the election process, including key generation, shuffling and joint-decryption, using the verificatum library by Douglas Wikström

Requirements
==============
You need

* java (version 7)
* sbt
* the agora_tally directory of the agora-tally project (clone then copy subdir to root of agora-verifier)
* the openstv project (git clone https://github.com/OpenTechStrategies/openstv.git)
* uuencode (apt-get install sharutils)

Packaging
==============
Run

* sbt clean proguard:proguard
* ./package.sh

this will generate an executable agora-verifier


Running
==============

./agora-verifier tally.tar.gz