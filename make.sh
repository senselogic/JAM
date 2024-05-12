#!/bin/sh
set -x
dmd -m64 jam.d
rm *.o
