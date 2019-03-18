#!/bin/bash

# TODO use version number in name
NAME=nitroinit-linux.bin

# Install necessary software
apt-get update
apt-get install -y python3 python3-pip swig libpcsclite-dev
pip3 install pyscard pyinstaller

# Build tool as single binary for Linux
# TODO is it possible/desirable to even include pcscd?
cd nitroinit
pyinstaller --noconfirm \
            --onefile \
	    --name $NAME \
	    nitroinit.py

# cleanup
mv dist/$NAME binaries
chown 1000:1000 binaries/$NAME
rm -rf dist build $NAME.spec

# TODO Windows build
# Build tool as single binary for Windows
#pyver=3.7.2
#pyurl=https://www.python.org/ftp/python/$pyver/python-$pyver.exe
#echo 'deb http://deb.debian.org/debian buster contrib' >> /etc/apt/sources.list
#dpkg --add-architecture i386 && apt-get update
#apt-get install -y wget gnupg2 wine32 winetricks
#wget $pyurl
##wget $pyurl.asc
##gpg --recv-keys 10250568 6A45C816 36580288 7D9DC8D2 18ADD4FF A4135B38 A74B06BF \
##		EA5BBD71 E6DF025C AA65421D 6F5E1540 F73C700D 487034E5
### TODO check for good signature and proceed or abort accordingly
##gpg --verify python-$pyver-amd64.exe.asc 
#WINEARCH=win32 winetricks msxml4
#cp python-$pyver.exe /root/.wine/drive_c/Windows/system32
#wine python-$pyver.exe /quiet InstallAllUsers=2 PrependPath=1 Include_test=0

