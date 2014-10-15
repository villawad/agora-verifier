#!/bin/sh


dir=`dirname $0`;
if [ x$dir = "x." ]
then
    dir=`pwd`
fi
base=`basename $0`;
path=$(mktemp -d)
tally=$(echo $(dirname $(readlink -e $1))/$(basename $1))

(cd $path; uudecode -o /dev/stdout $dir/$base | tar zxf -; cd $path/agora-verifier/; /usr/bin/env python3 verify.py $tally $2; rm -rf $path)
exit 0;
