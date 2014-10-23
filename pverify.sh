#!/bin/sh
if [ "$#" -ne 2 ] || ! [ -d "$2" ]; then
  echo "Usage: $0 <random_source> <tally_dir>" >&2
  exit 1
fi

command -v java >/dev/null 2>&1 || { echo >&2 "* I require java but it's not installed.  Aborting."; exit 1; }

java -Djava.security.egd=file:/dev/./urandom -classpath agora-verifier_2.10-1.0.jar org.agoravoting.agora.Verifier $1 $2
exit $?