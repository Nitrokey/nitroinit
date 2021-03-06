# Nitrokey Initialization Tool

Create and import GnuPG keys to the Nitrokey.

## Requirements

### Windows

### Linux

You need to install some libraries on your system. Users of Debian-based systems like Ubuntu do:

```
sudo apt update
sudo apt install pcscd python3-gpg python3-pyscard python3-cryptography
```

**Note: Because of [this bug](https://dev.gnupg.org/T4242) it is necessary to have GPGME version
1.13.0 or higher installed -- at least if you like to create a new key. Importing existing keys is working with older versions, too. (please see also the [corresponding
patch](https://dev.gnupg.org/rMf773ad392da57e6be4ade93c44baa5d2057c40b6))**

Then clone the repo recursively:
```
sudo apt install git
git clone --recursive https://github.com/Nitrokey/nitroinit/
```

## Usage
```
usage: nitroinit [-h] [--keyfile KEYFILE] [--expert] [--dry-run] [--reader READER]

Create and import GnuPG keys to the Nitrokey

optional arguments:
  -h, --help         show this help message and exit
  --keyfile KEYFILE  keyfile to import to the Nitrokey (e.g. exported from
                     GnuPG)
  --expert           Choose specific key algorithm attributes for newly
                     generated keys.
  --dry-run          Do not actually change anything on the Nitrokey. New keys
                     may are created.
  --reader READER    reader to use, in case there are multiple reader present
                     on the system
```

## Examples
### Create new keypair, backup and import it to Nitrokey
```
$ ./nitroinit.py

Nitroinit - Create and import GnuPG keys to the Nitrokey

No keyfile was provided. We create a new key, backup it and then import it to the Nitrokey.
You can provide an existing key via '--keyfile' flag. Please use '--help' for more information.
We start key creation now...

Please provide a user ID to identify your key.
Enter the name for the user ID: Nitroinit Test
Enter the email address for the user ID: nitroinit@example.com
Enter a comment to include (optional): 

Keys exported as /home/nitrokey/Nitroinit Test <nitroinit@example.com>-sec.gpg and /home/nitrokey/Nitroinit Test <nitroinit@example.com>-pub.gpg.

The following keys will be imported to the Nitrokey:

Nitroinit Test <nitroinit@example.com>
[S] rsa3072 b'B890EBA62B422E026BCB0B71D1A119CF6C9A5131' (2019-07-17 15:50:22)
[E] rsa3072 b'F3318B00BD43EE6F53B7380DD5E7923A7E2FC694' (2019-07-17 15:50:23)
[A] rsa3072 b'C68EC4298EEBC24EB25B7918F628B0AF15904159' (2019-07-17 15:50:23)

Please press enter to start importing... (Ctrl-C otherwise)

Using Reader: Nitrokey Nitrokey Pro (00005F120000000000000000) 00 00

WARNING! Existing keys on card will be overwritten!
Are you sure you want to proceed? Type 'yes' to proceed? yes

Enter Admin PIN for the card 00005F12: 
Key [S] imported to slot 1.
Key [E] imported to slot 2.
Key [A] imported to slot 3.

Import successful.
```

### Import already existing GnuPG key to Nitrokey
```
$ ./nitroinit.py --keyfile ecc_encrypted.gpg

Nitroinit - Create and import GnuPG keys to the Nitrokey

Please provide passphrase of the key or hit enter if no passphrase is used: 

More than one candidate for key slot 1 found.

0:  ecdsa256 b'ED3969EDD0574FF5C1E3A8D47C1C5EB897C14A8C' (2019-05-31 09:15:09)
1:  ecdsa256 b'D6CDA1DD0A7CA1D653C3F9ABA68D5C0B3DAF53CE' (2019-05-31 09:15:32)

Please choose which one to use (enter 'q' to abort): 0

The following keys will be imported to the Nitrokey:

ECC Keytest <ecc@example.com>
[S] ecdsa256 b'ED3969EDD0574FF5C1E3A8D47C1C5EB897C14A8C' (2019-05-31 09:15:09)
[E] ecdh256 b'DB8131F15297D679F8D3892B5E551CF8CE2FD3E7' (2019-05-31 09:15:09)

Please press enter to start importing... (Ctrl-C otherwise)

Using Reader: Nitrokey Nitrokey Pro (00005F120000000000000000) 00 00

WARNING! Existing keys on card will be overwritten!
Are you sure you want to proceed? Type 'yes' to proceed? yes

Enter Admin PIN for the card 00005F12: 
Key [S] imported to slot 1...
Key [E] imported to slot 2...

Import successful.
```

## Building binaries
**Note: This is currently not working properly**
```
docker-compose run build-binaries
```

## TODOs

* NIST-P 384, NIST-P 521, brainpoolP384r1, brainpoolP512r1 not working yet (GPG Agent states
  'Invalid Length')
* debug Nitrokey Start
* use travis to do automatically build binaries and update requirements.txt
* automatically build windows
* add option for gpg-agent usage (instead of pcscd)
* enable import of curve25519 keys (python-pgpdump related)
* add passphrase to backup key file
* Idea: simultaneous S/MIME key usage:
  * key slot 3 is used for authentication task which is not needed generally for common GnuPG task,
    therefore the slot might be used for S/MIME key instead; following are some notes what might need
    to be checked for that
  * do not create authentication subkey (like done right now)
  * either let import existing .p12 file to slot 3 or create a key with cert signing request and
    implement a possibility to import the signed cert to cardholder certificate
  * you might have a look at [OpenSC](https://github.com/OpenSC/OpenSC/) to have a look how the cert import is done there
