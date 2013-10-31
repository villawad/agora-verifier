agora-verifier
==============


agora-verifier performs tally and cryptographic verification of the election process, including key generation, shuffling and joint-decryption, using the verificatum library by Douglas Wikström

Requirements
==============
You need

* java
* sbt
* the agora-verifier direcotry of the agora-tally project
* the openstv project (git clone)

Packaging
==============
Run

* sbt clean proguard:proguard
* ./package.sh

this will generate an executable agora-verifier


Running
==============

agora-verifier tally.tar.gz
