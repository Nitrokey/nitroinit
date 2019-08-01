#!/usr/bin/env python3

'''
Copyright (c) 2019 Nitrokey UG

This file is part of Nitroinit.

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

import argparse
import getpass
import os
import sys
from pgpdump import AsciiData, BinaryData
from openpgpcard import OpenPGPCard
from keycreation import create_key


slots = {'S': 1, 'E': 2, 'A': 3}


def parse_packets(packets):
    '''parses packets of key and returns the userid and a dict of keys sorted by key usage flag'''

    userid = None
    sig_keys = []
    enc_keys = []
    aut_keys = []

    keys = {
            'S': sig_keys,
            'E': enc_keys,
            'A': aut_keys
            }

    # parse all packets of the key file
    for packet in packets:
        
        # get key data from Secret Key Packet
        if packet.name == "Secret Key Packet" or packet.name == "Secret Subkey Packet":
            key = {
                    'algo': packet.pub_algorithm_type,
                    'ctime_raw':    packet.raw_creation_time,
                    'ctime':   packet.creation_time,
                    'fp':       packet.fingerprint,
                  }

            if key['algo'] == "rsa":
                key.update({
                    'p':       packet.prime_p,
                    'q':       packet.prime_q,
                    'bit_len': packet.modulus_bitlen,
                    })
            elif key['algo'] == "ecdsa" or key['algo'] == "ecdh":
                key.update({
                    'oid':      packet.oid,
                    'bit_len':  packet.bitlen,
                    'private':  packet.private_d,
                    })
            else:
                raise # TODO add curve25519 keys

        # insert key in key list depending on the key usage flag
        if packet.name == "Signature Packet":
            for flag in packet.key_flags:
                if flag in keys:
                    keys[flag].append(key)

        if packet.name == "User ID Packet":
            userid = packet.user

    return userid, keys


def check_keys(keys):
    # for every list of keys for a specific key usage (=key slot) look for multiple candidates
    for flag, keylist in keys.items():

        # more than one key could be imported to Nitrokey
        # TODO ignore expired keys
        if len(keylist) > 1:
            print("\nMore than one candidate for key slot %i found.\n" % slots[flag])

            for i, key in enumerate(keylist):
                algo = key['algo'] + str(key['bit_len'])
                print("%i:  %s %s (%s)" % (i, algo, key['fp'], key['ctime']))
            selection = input("\nPlease choose which one to use (enter 'q' to abort): ")

            if selection == 'q':
                sys.exit()
            elif int(selection) >= 0 and int(selection) <= len(keylist):
                # remove all candidates but the one chosen
                keys[flag] = [keylist[int(selection)]]
            else:
                raise ValueError("Wrong input, please choose key to use")
    return keys


def print_summary(userid, keys):
    print("\nThe following keys will be imported to the Nitrokey:\n")
    print(userid)
    for flag, keylist in keys.items():
        if keylist:
            key = keylist[0]
            algo = key['algo'] + str(key['bit_len'])
            print("[%s] %s %s (%s)" % (flag, algo, key['fp'], key['ctime']))


def import_keys(keys):
    # connect with Nitrokey
    # TODO add error handling
    if reader is not None:
        card = OpenPGPCard(reader)
    else:
        card = OpenPGPCard()

    # check for existing keys and warn user
    for flag, slot in slots.items():
        # if fingerprint is present, a key is already stored
        # and only warn if (sub)key is actually overwritten
        if card.get_fingerprint(slot) and flag in keys.keys(): 
            print("\nWARNING! Existing keys on card will be overwritten!")
            response = input("Are you sure you want to proceed? Type 'yes' to proceed? ")
            print()
            if response != "yes":
                sys.exit(1)
            break;

    # start importing
    for flag, keylist in keys.items():
        if keylist:
            key = keylist[0]
            ctime_raw = key['ctime_raw']
            fp = key['fp']
            slot = slots[flag]

            if key['algo'] == 'rsa':
                p = key['p']
                q = key['q']
                bit_len = key['bit_len']
                card.import_rsakey(p, q, bit_len, ctime_raw, fp, slot)
                print("Key [%s] imported to slot %i." % (flag, slot))
            elif key['algo'] == "ecdsa" or key['algo'] == "ecdh":
                algo = key['algo']
                oid = key['oid']
                private = key['private']
                card.import_ecckey(algo, oid, private, ctime_raw, fp, slot)
                print("Key [%s] imported to slot %i..." % (flag, slot))
            else:
                raise # TODO add curve25519 keys


def main(keyfile, expert):
    passphrase = None

    print("\nNitroinit - Create and import GnuPG keys to the Nitrokey\n") 

    # No keyfile was given, thus create a new key and import this one
    if keyfile is None:
        print("No keyfile was provided. We create a new key, back it up and then import it to " + \
              "the Nitrokey.")
        print("You can provide an existing key via '--keyfile' flag. Please use '--help' for " + \
                "more information.")
        print("We start key creation now...\n")
        keyfile = create_key(expert)
    else:
        # get passphrase
        passphrase = getpass.getpass("Please provide passphrase of the key or hit enter if no " + \
                                     "passphrase is used: ")

    # open key file and parse it to get the key packets
    with open(keyfile, 'rb') as f:
        if keyfile.endswith('.asc') or keyfile.endswith('.txt'):
            data = AsciiData(f.read(), secret_keys=True, passphrase=passphrase)
        else:
            data = BinaryData(f.read(), secret_keys=True, passphrase=passphrase)

    userid, keys = parse_packets(data.packets())
    # TODO add test case for this

    keys = check_keys(keys)
    print_summary(userid, keys)

    # Do not import, dry-run only
    if dry:
        sys.exit(0)

    input("\nPlease press enter to start importing... (Ctrl-C otherwise)\n")

    import_keys(keys)

    print("\nImport successful.\n")

    # FIXME add passphrase to key backup


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Create and import GnuPG keys to the Nitrokey')
    parser.add_argument('--keyfile', dest='keyfile',
            help='keyfile to import to the Nitrokey (e.g. exported from GnuPG)')
    parser.add_argument('--expert', dest='expert', action='store_true',
            help='Choose specific key algorithm attributes for newly generated keys.')
    parser.add_argument('--dry-run', dest='dry', action='store_true',
            help='Do not actually change anything on the Nitrokey. New keys may are created.')
    parser.add_argument('--reader', nargs=1, type=int, dest='reader',
            help='reader to use, in case there are multiple reader present on the system')
    args = parser.parse_args()

    reader = args.reader
    dry = args.dry

    main(args.keyfile, args.expert)
