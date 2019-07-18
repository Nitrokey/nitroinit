#!/bin/env python3

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

import binascii
import getpass
import sys
from smartcard.sw.ISO7816_4ErrorChecker import ISO7816_4ErrorChecker
from smartcard.System import readers
from struct import pack


def int2bytes(value, length):
    result = []

    for i in range(0, length):
        result.append(value >> (i * 8) & 0xff)

    result.reverse()
    return result

def tlv_len(bytelist):
    '''Returns a list of bytes according to the ISO 7816-4 length field of TLV-structures for a
    given length'''

    if len(bytelist) >> 16:
        raise ValueError("Data is too big")
    elif len(bytelist) >> 8:
        data_len = [0x82, (len(bytelist) >> 8) & 0xff, len(bytelist) & 0xff]
    elif len(bytelist) >> 7:
        data_len = [0x81, len(bytelist) & 0xff]
    else:
        data_len = [len(bytelist)]
    return data_len

def print_apdu(apdu):
    print('APDU (%i bytes): \n%s' % (len(apdu), ' '.join(map(hex, apdu))))


class OpenPGPCard():
    
    def __init__(self, reader=None):
        self.version = None
        self.serial = None
        self.errorchecker = ISO7816_4ErrorChecker()
        self.connect(reader)
        self.get_aid()
        self.user_unlocked = False
        self.admin_unlocked = False

    def checkerrors(self, sw1, sw2):
        return self.errorchecker([], sw1, sw2)

    def connect(self, reader):
        SELECT_APPLET = [0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01,
                         0x24, 0x01, 0x00]
        r = readers()

        if len(r) > 1 and reader is None:
            print("\nMore than one card reader found, please specify which one to use.\n")
            for index,device in enumerate(r):
                print("Device %i: %s" % (index, device))
            print("\nUse '--help' for more information.\n")
            sys.exit()
        else:
            reader=0

        print("Using Reader: %s" % r[reader])
        self.connection = r[reader].createConnection()
        self.connection.connect()

        data, sw1, sw2 = self.connection.transmit(SELECT_APPLET)
        self.checkerrors(sw1, sw2)

    def get_aid(self):
        aid = self.get_data(0x004F)

        # TODO add some more fields?
        self.version = str(aid[6]) + '.' + str(aid[7])
        self.serial = binascii.hexlify(bytes(aid[10:14])).decode('ascii').upper()

    def construct_apdu(self, ins, p1, p2, data, le=None):
        if data is not None:
            if not isinstance(data, list):
                data = list(data)
            # if the length field does not follow the tlv standard
            if len(data) >> 8:
                apdu = [0x00, ins, p1, p2] + [0x00] + tlv_len(data)[1:] + data
            else:
                apdu = [0x00, ins, p1, p2, len(data)] + data

        else:
            apdu = [0x00, ins, p1, p2]

        if le is not None:
            apdu.append(le)

        return apdu

    def get_data(self, tag, debug=False):
        apdu = self.construct_apdu(0xCA, (tag >> 8) & 0xff, tag & 0xff, None, 0x00)

        if debug:
            print_apdu(apdu)

        data, sw1, sw2 = self.connection.transmit(apdu)
        # TODO implement GET RESPONSE for big data output

        self.checkerrors(sw1, sw2)
        return data

    def put_data(self, tag, data):
        '''OpenPGP Card PUT DATA function as in 7.2.8 of the specification (OpenPGP Card 3.3.1)'''

        # odd INS
        if (tag & 0xff) == 0x4D: # extended header list
            apdu = self.construct_apdu(0xDB, 0x3f, 0xff, data)
        # even INS
        else:
            apdu = self.construct_apdu(0xDA, (tag >> 8) & 0xff, tag & 0xff, data)

        indata, sw1, sw2 = self.connection.transmit(apdu)
        self.checkerrors(sw1, sw2)

    def verify_user(self):
        passw = getpass.getpass('Enter User PIN for the card ' + self.serial + ': ')
        self.verify(0x81, passw)
        # error check done in self.verify, thus verify succeeded
        self.user_unlocked = True
    
    def verify_once(self):
        passw = getpass.getpass('Enter User PIN for the card ' + self.serial + ': ')
        self.verify(0x82, passw)

    def verify_admin(self):
        passw = getpass.getpass('Enter Admin PIN for the card ' + self.serial + ': ')
        self.verify(0x83, passw)
        # error check done in self.verify, thus verify succeeded
        self.admin_unlocked = True
    
    def verify(self, p2, passw):
        '''OpenPGP Card VERIFY function as in 7.2.2 of the specification (OpenPGP Card 3.3.1)'''

        passw = list(passw.encode('utf-8'))
        apdu = self.construct_apdu(0x20, 0x00, p2 & 0xff, passw)

        indata, sw1, sw2 = self.connection.transmit(apdu)
        self.checkerrors(sw1, sw2)

    def import_rsakey(self, p, q, modulus_bitlen, ctime, fp, slot):
        keys = []
        priv_key_template = []
        
        # Value 65537 dec (0x010001) shall be accepted by every card for exponent e, other values
        # may not be accepted, so we just default to this one
        e = [0x00, 0x01, 0x00, 0x01]
        
        # key slot mapping
        slots = {1: 0xB6, 2: 0xB8, 3: 0xA4}

        # FIXME add sanity checks (does the card fullfill all caps etc.)
        if not self.admin_unlocked:
            self.verify_admin()
        self.set_algo_attr("rsa", slot, modulus_bitlen)

        # transform keys from int to list of bytes if necessary
        if isinstance(p, int):
            p = int2bytes(p, int(p.bit_length()/8))
        if isinstance(q, int):
            q = int2bytes(q, int(q.bit_length()/8))

        # construct Extended Header list
        # see 4.4.3.9 of the specification (OpenPGP Card 3.3.1)
        priv_key_template.extend(
                [0x91] + tlv_len(e) + [0x92] + tlv_len(p) + [0x93] + tlv_len(q))
        keys.extend(e + p + q)
        key_data = [0x5F, 0x48] + tlv_len(keys) + keys
        ext_header_list = [slots.get(slot), 0x00, 0x7F, 0x48, len(priv_key_template)] \
                        + priv_key_template + key_data
        self.put_data(0x4D, [0x4D] + tlv_len(ext_header_list) + ext_header_list)

        self.store_creationtime(ctime, slot)
        self.store_fingerprint(fp, slot)

        return

    def import_ecckey(self, algo, oid, private, ctime, fp, slot):
        priv_key_template = []

        # key slot mapping
        slots = {1: 0xB6, 2: 0xB8, 3: 0xA4}

        # FIXME add sanity checks (does the card fullfill all caps etc.)
        if not self.admin_unlocked:
            self.verify_admin()
        self.set_algo_attr(algo, slot, oid=oid)

        # transform keys from int to list of bytes if necessary
        if isinstance(private, int):
            private = int2bytes(private, (private.bit_length()+7)//8)

        # construct Extended Header list
        # see 4.4.3.9 of the specification (OpenPGP Card 3.3.1)
        priv_key_template.extend([0x92] + tlv_len(private))
        key_data = [0x5F, 0x48] + tlv_len(private) + private
        ext_header_list = [slots.get(slot), 0x00, 0x7F, 0x48, len(priv_key_template)] \
                        + priv_key_template + key_data
        self.put_data(0x4D, [0x4D] + tlv_len(ext_header_list) + ext_header_list)

        self.store_creationtime(ctime, slot)
        self.store_fingerprint(fp, slot)
        return

    def set_algo_attr(self, algo, slot, modulus_bitlen=None, oid=None):
        if (slot not in (1, 2, 3)):
            raise ValueError("Wrong slot number! There exist only key slots 1, 2 and 3")

        if algo == "rsa":
            data = [0x01, (modulus_bitlen >> 8) & 0xff, modulus_bitlen >> 0xff, 0x00, 0x20, 0x00]
        elif algo == "ecdsa" or algo == "ecdh":
            if algo == "ecdh" and slot == 2:
                data = [18]
                data.extend(list(oid))
            elif algo == "ecdsa" and slot in (1,3):
                data = [19]
                data.extend(list(oid))
            else:
                raise ValueError("ECC type does not match card slot")
        else:
            raise ValueError("Key type not implemented!")
        self.put_data(0xC0 + slot, data)

    def store_creationtime(self, ctime, slot):
        if (slot not in (1, 2, 3)):
            raise ValueError("Wrong slot number! There exist only key slots 1, 2 and 3")

        # TODO check for reasonable value/only transform if necessary
        # transform ctime to Big-Endian
        ctime = pack('>I', ctime)
        self.put_data(0xCD + slot, ctime)

    def get_creationtime(self, slot):
        '''Reads creation time for slot from card and returns seconds since Unix time'''
        if (slot not in (1, 2, 3)):
            raise ValueError("Wrong slot number! There exist only key slots 1, 2 and 3")

        # get 'Application Related Data' DO (6E)
        data = self.get_data(0x6e)

        # this DO contains much more than the fingerprints (-> we need to calculate position)
        # see 9.1 of OpenPGP Card specification for list of values
        ctime_start = 0xd8 + slot * 4 # (each fingerprint being 4 bytes long, first at 0xdc)
        ctime = data[ctime_start:ctime_start + 4]

        return int.from_bytes(ctime, byteorder='big')

    def store_fingerprint(self, fp, slot):
        if (slot not in (1, 2, 3)):
            raise ValueError("Wrong slot number! There exist only key slots 1, 2 and 3")

        # TODO check for reasonable value/only transform if necessary
        self.put_data(0xC6 + slot, list(binascii.unhexlify(fp)))

    def get_fingerprint(self, slot):
        if (slot not in (1, 2, 3)):
            raise ValueError("Wrong slot number! There exist only key slots 1, 2 and 3")

        # get 'Application Related Data' DO (6E)
        data = self.get_data(0x6e)

        # this DO contains much more than the fingerprints (-> we need to calculate position)
        # see 9.1 of OpenPGP Card specification for list of values
        fpr_start = 0x48 + slot * 20 # (each fingerprint being 20 bytes long, first at 0x60)
        fpr = binascii.hexlify(bytes(data[fpr_start:fpr_start + 20])).decode('ascii').upper()

        return fpr
