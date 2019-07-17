#!/bin/env python3

'''
Copyright (c) 2019 Nitrokey UG

This file is part of nitroinit.

Nitroinit is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

Nitroinit is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Nitroinit. If not, see <http://www.gnu.org/licenses/>.

SPDX-License-Identifier: GPL-3.0
'''

""" Create a new PGP key and store it on disk for backup purposes """

import gpg
import os
import sys


def input_keyattr():
    algo = size = None

    print("Please select what kind of key you want:\n   (1) RSA\n   (2) ECC")
    algo = input("Your selection? ")

    if algo == "1":
        algo = "rsa"
        size = input("\nWhat keysize do you want (2048, 3076, 4096)? ")
        print()
        if size in ["2048", "3076", "4096"]:
            algorithm = "{0}{1}".format(algo, size)
        else:
            raise ValueError("Wrong selection, please choose (2048, 3076, 4096).")

    elif algo == "2":
        raise ValueError("ECC key creation not working yet")
        print("\nPlease select which elliptic curve you want:")
        # TODO add curve25519 if supported
        print("   (3) NIST P-256")
        print("   (4) NIST P-384")
        print("   (5) NIST P-521")
        print("   (6) Brainpool P-256")
        print("   (7) Brainpool P-384")
        print("   (8) Brainpool P-512")
        algorithm = input("Your selection? ")
        print()
        # FIXME ecc not fully working with GPGME find out why!
    else:
        raise ValueError("Wrong selection, please choose 1 (rsa) or 2 (ecc).")

    return algorithm


def input_userid():
    uid = {}
    print("Please provide a user ID to identify your key.")
    uid['name'] = input("Enter the name for the user ID: ")
    uid['email'] = input("Enter the email address for the user ID: ")
    uid['cmnt'] = input("Enter a comment to include (optional): ")
    print()
    return uid


def create_key(expert=False):
    # TODO do not use rsa3072 for NK Start
    algorithm = "rsa3072" # default values
    exp_time = 0
    expires = False

    c = gpg.Context()

    # let user change key attributes
    if expert:
        algorithm = input_keyattr()

    # ask user for User ID
    uid = input_userid() # FIXME ask for expiration time here as well

    # craft userid
    if len(uid['cmnt']) > 0:
        userid = "{0} ({1}) <{2}>".format(uid['name'], uid['cmnt'], uid['email'])
    else:
        userid = "{0} <{1}>".format(uid['name'], uid['email'])

    # generate main key, encryption subkey and authentication subkey
    newkey = c.create_key(userid, algorithm, exp_time, expires, certify=True, sign=True)
    key = c.get_key(newkey.fpr, secret=True)
    esub = c.create_subkey(key, algorithm, exp_time, expires, encrypt=True)
    asub = c.create_subkey(key, algorithm, exp_time, expires, authenticate=True)

    # FIXME ask for location of backup keys
    keyfile = os.path.expanduser("~/{0} <{1}>-sec.gpg".format(uid['name'], uid['email']))
    keyfile_pub = os.path.expanduser("~/{0} <{1}>-pub.gpg".format(uid['name'], uid['email']))

    # export secret and public keys to files for backup
    try:
        pubdata = c.key_export(newkey.fpr)
        secdata = c.key_export_secret(newkey.fpr)
    except:
        raise

    if pubdata is not None:
        with open(keyfile_pub, "wb") as f:
            f.write(pubdata)
    else:
        pass # TODO add proper exception

    if secdata is not None:
        with open(keyfile, "wb") as f:
            f.write(secdata)
        os.chmod(keyfile, 0o600)
    else:
        pass # TODO add proper exception

    print("Keys exported as {0} and {1}.".format(keyfile, keyfile_pub)) 

    # delete secret key from keyring (as it will be imported to the Nitrokey)
    # op_delete_ext accepts two flags which can be set bit-wise
    # 1 - delete secret keys; 2 - do not ask user before deletion
    # we want both, thus using flag value '3'
    c.op_delete_ext(key, 3) # TODO add error handling

    # import public key again
    with open(keyfile_pub, "rb") as f:
        pubkey = f.read()
    c.key_import(pubkey) # TODO add error handling

    # provide path to secret keyfile
    return keyfile


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == "--expert":
        create_key(expert=True)
    else:
        create_key()
