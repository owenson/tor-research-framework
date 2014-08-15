#!/bin/bash

# Produce multiple tor builds from the same (C) source directory
# Each build has a varying level of security:
#   features: enable features, disable security
#   default: default configuration
#   harden: disable features, enable extra security
# This assists in determining vulnerable features during testing

# Run this script in a directory containing the tor source distribution

PREFIX_BASE=$HOME/tor
EXT_DIR=$HOME/tor/external
EXT_INCDIR=$HOME/tor/external/include
EXT_LIBDIR=$HOME/tor/external/lib

 
# Required header and library for dmalloc
# We could also -DFINI_DMALLOC=0, but instead we turn off -Werror
CPPFLAGS="-I$EXT_INCDIR"
LDFLAGS="-L$EXT_LIBDIR"
# For the threads tests to run, the number below should be set between 5 and 30
# This asks dmalloc to wait for the thread manager to start up
# These variables were generated using "dmalloc -o <number>", 
# then modified to correctly parse in bash
# On my system, lockon 3 passes, but 2 fails then hangs, and 0 goes recursive
DMALLOC_OPTIONS="lockon=3"
export DMALLOC_OPTIONS
# Set the OS X library path to include the dmalloc library
export DYLD_FALLBACK_LIBRARY_PATH=$DYLD_FALLBACK_LIBRARY_PATH:$EXT_LIBDIR

# On my system, libevent and (the working version of) openssl 
# are in a non-system directory
# We also use dmalloc across all builds to catch memory errors early
# We disable documentation and dependency tracking to speed up the builds
CC_OPTS="--with-libevent-dir=$EXT_LIBDIR --with-openssl-dir=$EXT_LIBDIR --with-dmalloc CPPFLAGS=$CPPFLAGS LDFLAGS=$LDFLAGS --disable-asciidoc --disable-dependency-tracking"
MAKE="make -j4"

date

# If any of these builds fail, we want to stop there and fix the error

# Enable extras, disable security, use (older) system libraries
# We could also use libnatpmp if available: --enable-nat-pmp
$MAKE clean && \
./configure --prefix=$PREFIX_BASE/tor-features-install $CC_OPTS --enable-gcc-warnings-advisory --enable-instrument-downloads --enable-upnp --with-libminiupnpc-dir=$EXT_LIBDIR --disable-gcc-hardening --disable-linker-hardening && $MAKE && $MAKE test && $MAKE install && date && \
\
# Use defaults wherever possible, including (older) system libraries
$MAKE clean && \
./configure --prefix=$PREFIX_BASE/tor-default-install $CC_OPTS --enable-gcc-warnings-advisory && $MAKE && $MAKE test && $MAKE install && date && \
\
# Disable extras, options, enable security, use (newer) libraries
$MAKE clean && \
./configure --prefix=$PREFIX_BASE/tor-harden-install $CC_OPTS --enable-gcc-warnings-advisory --disable-curve25519 --disable-transparent --disable-largefile --enable-expensive-hardening --with-openssl-dir=$EXT_LIBDIR --with-zlib-dir=$EXT_LIBDIR && $MAKE && $MAKE test && $MAKE install && date && \

$MAKE clean

date
