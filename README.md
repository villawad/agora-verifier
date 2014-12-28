agora-verifier
==============


agora-verifier performs tally and cryptographic verification of the election process, including key generation, shuffling and joint-decryption, using the verificatum library by Douglas Wikström

Requirements
==============
You need

* java (version 7)

    sudo add-apt-repository ppa:webupd8team/java
    sudo apt-get update
    sudo apt-get install oracle-java7-installer
    sudo apt-get install oracle-java7-set-default

if you need to revert to java 8 later

    sudo apt-get install oracle-java8-set-default

* sbt (version 0.13.7 used here)

    wget https://dl.bintray.com/sbt/debian/sbt-0.13.7.deb
    dpkg -i sbt-0.13.7.deb

* the agora_tally directory of the agora-tally project

    git clone https://github.com/agoravoting/agora-tally.git
    mv agora-tally/agora_tally .

* the openstv directory of the openstv project

    git clone https://github.com/agoravoting/openstv.git
    mv openstv/ openstv2
    mv openstv2/openstv .

* the agora-results directory of the agora-results directory and the executable python script

    git clone https://github.com/agoravoting/agora-results.git
    mv agora-results/ agora-results2
    mv agora-results2/agora_results .
    mv agora-results2/agora-results .

* uuencode

    apt-get install sharutils

Packaging
==============
Run

* sbt clean proguard:proguard
* ./package.sh

this will generate an executable agora-verifier


Running
==============

./agora-verifier tally.tar.gz