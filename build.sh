#!/bin/bash
#
# Need to install the following on Ubuntu 12.04:
# - cmake
# - libgtk2.0-dev
# - libxtst-dev
#
# If you find other deps, add them here

NCPU=`cat /proc/cpuinfo |grep vendor_id |wc -l`
let NCPU=$NCPU+2
echo "Will build with 'make -j$NCPU' ... please edit this script if incorrect."

set -x
rm -rf cmake-build
mkdir -p cmake-build
cd $_
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$NCPU && cp -a 1pass ..
cd ..

