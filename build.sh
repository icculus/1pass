#!/bin/sh
#
# Need to install the following on Ubuntu 12.04:
# - cmake
# - libgtk2.0-dev
# - libxtst-dev
#
# If you find other deps, add them here

cmake -DCMAKE_BUILD_TYPE=Release .
make
