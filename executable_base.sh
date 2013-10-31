#!/bin/sh


dir=`dirname $0`;
if [ x$dir = "x." ]
then
    dir=`pwd`
fi
base=`basename $0`;
path=$(mktemp -d)
tally=$(realpath $1)
(cd $path; uudecode -o /dev/stdout $dir/$base | tar zxf -; cd $path/agora-verifier/; python verify.py $tally)
exit 0;
