#!/bin/bash

CRTFILE=~/.iPKCS11.server.crt
URLFILE=~/.iPKCS11.url

set -e

if [ -e $URLFILE ]; then
    SERVER="$(cat $URLFILE | sed 'svhttps://vv')"
else
    echo "$URLFILE: No such file or directory"
    exit 1
fi

if [ -e $CRTFILE ]; then
    echo -n "$CRTFILE exists. overwrite? [y/N] "
    read ans
    if [ ! "$ans" = y ]; then
        exit 1
    fi
fi

openssl s_client -connect "$SERVER" << EOF | grep -A100 "BEGIN CERTIFICATE"|grep -B100 "END CERTIFICATE" > $CRTFILE
QUIT
EOF

echo "--- Certificate saved to $CRTFILE."
echo "--- You should check that the servers md5sum of the"
echo -n "--- certificate is "

if type -p md5 > /dev/null; then
    echo "$(md5 $CRTFILE|awk '{ print $4 }')." | tr [:lower:] [:upper:]
elif type -p md5sum > /dev/null; then
    echo "$(md5sum $CRTFILE|awk '{ print $1 }')." | tr [:lower:] [:upper:]
else
    echo "the same as the md5sum of $CRTFILE."
fi

