#!/bin/bash

# Produce multiple tor builds from the same (C) source directory
# Each build has a varying level of security:
#   features: enable features, disable security
#   default: default configuration
#   harden: disable features, enable extra security
# This assists in determining vulnerable features during testing

# Run this script in the directory containing the tor source distribution

PREFIX_BASE=$HOME/tor
EXTRA_LIBDIR=$HOME/tor/libs

CC_OPTS="--with-libevent-dir=$EXTRA_LIBDIR --disable-asciidoc --disable-dependency-tracking"
MAKE="make"

date

# If any of these builds fail, we want to stop there and fix the error

# Enable extras, disable security, use (older) system libraries
# We could also use libnatpmp if available: --enable-nat-pmp
$MAKE clean && \
./configure --prefix=$PREFIX_BASE/tor-features-install $CC_OPTS --enable-gcc-warnings-advisory --enable-instrument-downloads --enable-upnp --with-libminiupnpc-dir=$EXTRA_LIBDIR --disable-gcc-hardening --disable-linker-hardening && $MAKE && $MAKE test && $MAKE install && date && \
\
# Use defaults wherever possible, including (older) system libraries
$MAKE clean && \
./configure --prefix=$PREFIX_BASE/tor-default-install $CC_OPTS --enable-gcc-warnings-advisory && $MAKE && $MAKE test && $MAKE install && date && \
\
# Disable extras, options, enable security, use (newer) libraries
$MAKE clean && \
./configure --prefix=$PREFIX_BASE/tor-harden-install $CC_OPTS --enable-gcc-warnings --disable-curve25519 --disable-transparent --disable-largefile --enable-expensive-hardening --with-openssl-dir=$EXTRA_LIBDIR --with-zlib-dir=$EXTRA_LIBDIR && $MAKE && $MAKE test && $MAKE install && date && \

$MAKE clean

date
