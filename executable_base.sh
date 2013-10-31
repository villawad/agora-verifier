#!/bin/sh


dir=`dirname $0`;
if [ x$dir = "x." ]
then
    dir=`pwd`
fi
base=`basename $0`;
path=$(mktemp -d)

(cd $path; uudecode -o /dev/stdout $dir/$base | tar zxf -; cd $path/agora-verifier/; python verify.py $1)
exit 0;
