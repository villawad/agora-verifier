#!/bin/sh

rm -r -f dist
mkdir dist
cp -r agora_tally dist
cp -r openstv dist
cp target/scala-2.10/proguard/agora-verifier_2.10-1.0.jar dist
cp pverify.sh dist
cp verify.py dist
tar zcf agora-verifier.tar.gz dist --transform s/dist/agora-verifier/
