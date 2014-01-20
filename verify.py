#!/usr/bin/env python

from agora_tally import tally
import sys
import os
import hashlib
import subprocess
import json
import tarfile
from tempfile import mkdtemp


def verify_pok_plaintext(pk, proof, ciphertext):
    '''
    verifies the proof of knowledge of the plaintext, given encrypted data and
    the public key

    Format:
        * "ballot" must be a dictionary with keys "alpha", "beta", "commitment",
          "challenge", "response", and values must be integers.
        * "pk" must be a dictonary with keys "g", "p", and values must be
          integers.
    # http://courses.csail.mit.edu/6.897/spring04/L19.pdf - 2.1 Proving Knowledge of Plaintext
    '''

    pk_p = pk['p']
    pk_g = pk['g']
    commitment = int(proof['commitment'])
    response = int(proof['response'])
    challenge =  int(proof['challenge'])
    alpha = int(ciphertext['alpha'])

    pk = dict(
        p=pk_p,
        g=pk_g
    )
    ballot = dict(
        commitment=commitment,
        response=response,
        challenge=challenge,
        alpha=alpha
    )

    # verify the challenge is valid
    hash = hashlib.sha256()
    hash.update(str(alpha) + "/" + str(commitment))
    challenge_calculated = int(hash.hexdigest(), 16)
    assert challenge_calculated == challenge

    first_part = pow(pk_g, response, pk_p)
    second_part = (commitment * pow(alpha, challenge, pk_p)) % pk_p

    # check g^response == commitment * (g^t) ^ challenge == commitment * (alpha) ^ challenge
    assert first_part == second_part

def verify_votes_pok(pubkeys, path, tally, hash):
    with open(path, mode='r') as votes_file:
        num_questions = len(tally['counts'])

        for i in xrange(num_questions):
            pubkeys[i]['g'] = int(pubkeys[i]['g'])
            pubkeys[i]['p'] = int(pubkeys[i]['p'])

        found = False
        for line in votes_file:
            vote = json.loads(line)
            if hash and not found and hashlib.sha256(line[:-1]).hexdigest() == hash:
                found = True
                print("* Hash of the vote was successfully found")

            if not hash or (hash is not None and found):
                for i in xrange(num_questions):
                    verify_pok_plaintext(pubkeys[i], vote['proofs'][i], vote['choices'][i])

        if hash is not None and not found:
            print("* ERROR: vote hash %s NOT FOUND" % hash)
            sys.exit(1)

if __name__ == "__main__":
    RANDOM_SOURCE=".rnd"

    # untar the plaintexts
    dir_path = mkdtemp("tally")
    tally_gz = tarfile.open(sys.argv[1], mode="r:gz")

    # second argument is the hash of the vote
    hash = None
    if len(sys.argv) > 2:
        hash = sys.argv[2]
        print("* Vote hash %s given, we will search the corresponding ballot.." % hash)

    tally_gz.extractall(path=dir_path)
    print("* extracted to " + dir_path)

    tally = tally.do_dirtally(dir_path)
    tally_s = json.dumps(tally)

    pubkeys_path = os.path.join(dir_path, "pubkeys_json")
    pubkeys = json.loads(open(pubkeys_path).read())
    print("* verifying proofs of knowledge of the plaintexts...")
    verify_votes_pok(pubkeys, os.path.join(dir_path, 'ciphertexts_json'), tally, hash)
    print("* proofs of knowledge of plaintexts OK")

    if hash is not None:
        print("* ballot hash verification OK")
        sys.exit(0)

    tallyfile = dir_path + "/result_json"

    hashone = hashlib.md5(open(tallyfile).read()).hexdigest()
    hashtwo = hashlib.md5(tally_s).hexdigest()
    if (hashone != hashtwo):
        print("* tally verification FAILED")
        sys.exit(0)

    print("* tally verification OK")

    print "* running './pverify.sh " + RANDOM_SOURCE + " " + dir_path + "'"
    subprocess.call(['./pverify.sh', RANDOM_SOURCE, dir_path])
