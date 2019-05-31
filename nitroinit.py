#!/bin/env python3

'''
Copyright (c) 2019 Nitrokey UG

This file is part of nitroinit.

Key Tool is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

Key Tool is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Nitrokey App. If not, see <http://www.gnu.org/licenses/>.

SPDX-License-Identifier: GPL-3.0
'''


import argparse
import getpass
import os
import sys
from pgpdump import AsciiData, BinaryData
from openpgpcard import OpenPGPCard


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
            key = {'algo': packet.pub_algorithm_type}

            if key['algo'] == "rsa":
                key.update({
                    'p':       packet.prime_p,
                    'q':       packet.prime_q,
                    'bit_len': packet.modulus_bitlen,
                    'ctime':   packet.raw_creation_time,
                    'fp':      packet.fingerprint,
                    })
            elif key['algo'] == "ecdsa" or key['algo'] == "ecdh":
                key.update({
                    'oid':      packet.oid,
                    'bit_len':  packet.bitlen,
                    'private':  packet.private_d,
                    'ctime':    packet.raw_creation_time,
                    'fp':       packet.fingerprint,
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
                print("%i:  %s %s" % (i, algo, key['fp']))
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
            print("[%s] %s %s" % (flag, algo, key['fp']))


def import_keys(keys):
    # connect with Nitrokey
    if reader is not None:
        card = OpenPGPCard(reader)
    else:
        card = OpenPGPCard()

    for flag, keylist in keys.items():
        if keylist:
            key = keylist[0]
            ctime = key['ctime']
            fp = key['fp']
            slot = slots[flag]

            # start importing
            if key['algo'] == 'rsa':
                p = key['p']
                q = key['q']
                bit_len = key['bit_len']
                card.import_rsakey(p, q, bit_len, ctime, fp, slot)
                print("Key [%s] imported to slot %i..." % (flag, slot))
            elif key['algo'] == "ecdsa" or key['algo'] == "ecdh":
                algo = key['algo']
                oid = key['oid']
                private = key['private']
                card.import_ecckey(algo, oid, private, ctime, fp, slot)
                print("Key [%s] imported to slot %i..." % (flag, slot))
            else:
                raise # TODO add curve25519 keys


def main():

    # get passphrase
    passphrase = getpass.getpass("Please provide passphrase of the key: ")

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

    input("\nPlease press enter to start importing... (Ctrl-C otherwise)\n")

    import_keys(keys)

    print("\nImport successful.\n")


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Generating and importing keys to Nitrokey devices')
    parser.add_argument('--reader', nargs=1, type=int, dest='reader',
            help='reader to use, in case there are multiple reader present on the system')
    parser.add_argument('--keyfile', dest='keyfile', required=True,
            help='keyfile to import to the Nitrokey (e.g. exported from GnuPG)')
    args = parser.parse_args()

    keyfile = args.keyfile
    reader = args.reader

    main()
