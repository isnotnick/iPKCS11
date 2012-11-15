#!/bin/bash
if [ "$1" == "" ]; then
    echo "$0 <public_key>"
else
    ssh-keygen -e -f "$1" -m PEM 
fi
