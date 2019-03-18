# Nitrokey Initialization Tool

Nitroinit facilitates the import of GnuPG keys to the Nitrokey.

## Requirements

### Windows

### Linux

You need to install pcscd on your system. Users of Debian-based systems like Ubuntu do:

```
sudo apt-get update
sudo apt-get install pcscd
```

## Usage
```
usage: nitroinit.py [-h] [--reader READER] --keyfile KEYFILE

Generating and importing keys to Nitrokey devices

optional arguments:
  -h, --help         show this help message and exit
  --reader READER    reader to use, in case there are multiple reader present
                     on the system
  --keyfile KEYFILE  keyfile to import to the Nitrokey (e.g. exported from
                     GnuPG)
```

## Building

```
docker-compose run build-binaries
```

## TODOs

* automatically build windows
* add --dry-run option
* warn about existing keys
* print ctime in key choose function
* enable import of keys protected with passphrase (python-pgpdump related)
* enable import of ECC keys (python-pgpdump related)
* add option for generating new keys (outside of Nitrokey, thus with backup)
