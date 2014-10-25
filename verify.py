#!/usr/bin/env python3

from agora_tally import tally as agora_tally
import sys
import os
import signal
import hashlib
import shutil
import subprocess
import json
import tarfile
import traceback
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
    hash.update(("%d/%d" % (alpha, commitment)).encode('utf-8'))
    challenge_calculated = int(hash.hexdigest(), 16)
    assert challenge_calculated == challenge

    first_part = pow(pk_g, response, pk_p)
    second_part = (commitment * pow(alpha, challenge, pk_p)) % pk_p

    # check g^response == commitment * (g^t) ^ challenge == commitment * (alpha) ^ challenge
    assert first_part == second_part

def verify_votes_pok(pubkeys, dir_path, tally, hash):
    num_invalid_votes = 0
    linenum = 0
    with open(os.path.join(dir_path, 'ciphertexts_json'), mode='r') as votes_file:
        num_questions = len(tally['counts'])
        # we will write the ciphertexts for each question in here
        outvotes_files = []
        ldir = os.listdir(dir_path)
        ldir.sort()
        for question_dir in ldir:
            question_path = os.path.join(dir_path, question_dir)
            if not os.path.isdir(question_path):
              continue
            outvotes_path = os.path.join(question_path, 'ciphertexts_json')
            outvotes_files.append(open(outvotes_path, 'w'))

        for i in range(num_questions):
            pubkeys[i]['g'] = int(pubkeys[i]['g'])
            pubkeys[i]['p'] = int(pubkeys[i]['p'])

        found = False
        for line in votes_file:
            vote = json.loads(line)
            linenum += 1

            choice_num = 0
            for f in outvotes_files:
              f.write(json.dumps(vote['choices'][choice_num], separators=(",", ":")))
              f.write("\n")
              choice_num += 1

            if linenum % 1000 == 0:
                print("* verified %d votes (%d invalid).." % (linenum, num_invalid_votes))
            if hash and not found and hashlib.sha256(line[:-1].encode('utf-8')).hexdigest() == hash:
                found = True
                print("* Hash of the vote was successfully found: %s" % line)

            if not hash or (hash is not None and found):
                for i in range(num_questions):
                    try:
                        verify_pok_plaintext(pubkeys[i], vote['proofs'][i], vote['choices'][i])
                    except:
                        num_invalid_votes += 1

        for f in outvotes_files:
          f.close()
        if hash is not None and not found:
            print("* ERROR: vote hash %s NOT FOUND" % hash)
            raise Exception()
    print("* ..finished. Verified %d votes (%d invalid)" % (linenum, num_invalid_votes))
    return num_invalid_votes

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


    def sig_handler(signum, frame):
        print("\nTerminating: deleting temporal files..")
        shutil.rmtree(dir_path)
        exit(1)
    signal.signal(signal.SIGTERM, sig_handler)
    signal.signal(signal.SIGINT, sig_handler)

    tally_gz.extractall(path=dir_path)
    print("* extracted to " + dir_path)

    tallyfile = dir_path + "/result_json"
    tallyfile_s = open(tallyfile).read()
    tallyfile_json = json.loads(tallyfile_s)
    hashone = hashlib.md5(tallyfile_s.encode('utf-8')).hexdigest()

    print("# Results ##########################################")
    i = 1
    print("total number of votes (including blank/invalid votes): %d" % tallyfile_json['total_votes'])
    for q in tallyfile_json['counts']:
        print("Question #%d: %s\n" % (i, q['question']))
        i += 1
        print("number of options available: %d" % len(q['answers']))
        print("\nRaw winning options (unordered!):")
        for opt in q['winners']:
            print(" - %s" % opt)
        print("####################################################\n")

    pubkeys_path = os.path.join(dir_path, "pubkeys_json")
    pubkeys = json.loads(open(pubkeys_path).read())

    print("* verifying proofs of knowledge of the plaintexts...")
    try:
        num_encrypted_invalid_votes = verify_votes_pok(
            pubkeys,
            dir_path,
            tallyfile_json,
            hash)
        print("* proofs of knowledge of plaintexts OK (%d invalid)" % num_encrypted_invalid_votes)

        if hash is not None:
            print("* ballot hash verification OK")
            shutil.rmtree(dir_path)
            sys.exit(0)

        tally = agora_tally.do_dirtally(
            dir_path,
            encrypted_invalid_votes=num_encrypted_invalid_votes)
        tally_s = json.dumps(tally, sort_keys=True, indent=4, separators=(',', ': '))
        hashtwo = hashlib.md5(tally_s.encode('utf-8')).hexdigest()

        #TODO: fix when we have integration with agora-tongo
        if (hashone != hashtwo):
            print("* tally verification FAILED")
            sys.exit(1)

        print("* tally verification OK")

        print("* running './pverify.sh " + str(RANDOM_SOURCE) + " " + dir_path + "'")
        pverify_ret = subprocess.call(['./pverify.sh', RANDOM_SOURCE, dir_path])
        if (pverify_ret != 0):
            print("* mixing and decryption verification FAILED")
            raise Exception()

        # check if plaintexts_json is generated correctly from the already verified
        # plaintexts raw proofs
        i = 0
        ldir = os.listdir(dir_path)
        ldir.sort()
        for question_dir in ldir:
            question_path = os.path.join(dir_path, question_dir)
            if not os.path.isdir(question_path):
                continue

            print("* processing question_dir " + question_dir)

            if not question_dir.startswith("%d-" % i):
                print("* invalid question dirname FAILED")
                raise Exception()

            if i >= len(tally["counts"]):
                print("* invalid question dirname FAILED")
                raise Exception()

            cwd = os.getcwd()
            vmnc = os.path.join(os.getcwd(), "vmnc.sh")

            # verify plaintexts raw conversion
            print("* running '" + vmnc + " " + str(RANDOM_SOURCE) + " -plain -outi json proofs/PlaintextElements.bt "
                "plaintexts_json2'")
            subprocess.call([vmnc, RANDOM_SOURCE, "-plain", "-outi", "json",
                            "proofs/PlaintextElements.bt", "plaintexts_json2"],
                            cwd=question_path)

            path1 = os.path.join(dir_path, question_dir, "plaintexts_json")
            path2 = os.path.join(dir_path, question_dir, "plaintexts_json2")

            path1_s = open(path1).read()
            path2_s = open(path2).read()
            hash1 = hashlib.md5(path1_s.encode('utf-8')).hexdigest()
            hash2 = hashlib.md5(path2_s.encode('utf-8')).hexdigest()
            if (hash1 != hash2):
                print("* plaintexts_json verification FAILED")
                raise Exception()
            print("* plaintexts_json verification OK")


            # verify ciphertexts raw conversion
            print("* running '" + vmnc + " " + str(RANDOM_SOURCE) + " -ciphs -ini json ciphertexts_json ciphertexts_raw'")
            subprocess.call([vmnc, RANDOM_SOURCE, "-ciphs", "-ini", "json",
                            "ciphertexts_json", "ciphertexts_raw"],
                            cwd=question_path)

            path1 = os.path.join(dir_path, question_dir, "ciphertexts_raw")
            path2 = os.path.join(dir_path, question_dir, "proofs", "CiphertextList00.bt")

            path1_s = open(path1, "rb").read()
            path2_s = open(path2, "rb").read()
            hash1 = hashlib.md5(path1_s).hexdigest()
            hash2 = hashlib.md5(path2_s).hexdigest()
            if (hash1 != hash2):
                print("* ciphertexts_json verification FAILED")
                raise Exception()
            print("* ciphertexts_json verification OK")

            i += 1
    except Exception as e:
        print("* tally verification FAILED due to an error processing it:")
        traceback.print_exc()
        if os.path.exists(dir_path):
            shutil.rmtree(dir_path)
        sys.exit(1)
