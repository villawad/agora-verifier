#!/usr/bin/env python

from agora_tally import tally
import sys
import hashlib
import subprocess
import json
import tarfile
from tempfile import mkdtemp

RANDOM_SOURCE=".rnd"

# untar the plaintexts
dir_path = mkdtemp("tally")
tally_gz = tarfile.open(sys.argv[1], mode="r:gz")
tally_gz.extractall(path=dir_path)
print("* extracted to " + dir_path)

tally = tally.do_dirtally(dir_path)
tally = json.dumps(tally)

tallyfile = dir_path + "/result_json"

hashone = hashlib.md5(open(tallyfile).read()).hexdigest()
hashtwo = hashlib.md5(tally).hexdigest()
if (hashone != hashtwo):
    print("* tally verification FAILED")
    sys.exit(0)

print("* tally verification OK")
print "* running './pverify.sh " + RANDOM_SOURCE + " " + dir_path + "'"
subprocess.call(['./pverify.sh', RANDOM_SOURCE, dir_path])
