#!/bin/bash

rm -f submission.tar.gz
tar -czvf submission.tar.gz reflector.py Makefile README
cp submission.tar.gz $DESKTOP/submission.tar.gz
echo "exported"
