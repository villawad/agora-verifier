#!/bin/bash
command -v java >/dev/null 2>&1 || { echo >&2 "* I require java but it's not installed.  Aborting."; exit 1; }

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

java -Djava.security.egd=file:/dev/./urandom -classpath $DIR/agora-verifier_2.10-1.0.jar org.agoravoting.agora.Vmnc "$@"
