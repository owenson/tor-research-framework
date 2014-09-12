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

O_FAST="-Ofast -ffp-contract=fast -fslp-vectorize-aggressive -fstrict-enums"
O_SIZE="-Oz"
O_MIN="-O1"
O_NONE="-O0"

# to aid debugging
#O_FAST=$O_NONE
#O_SIZE=$O_NONE
#O_MIN=$O_NONE

# dmalloc doesn't seem to work on the latest builds without -DFINI_DMALLOC=1,
# which is difficult to configure.
# We might use the system guard malloc instead.

CPPFLAGS="-I$EXT_INCDIR"
LDFLAGS="-L$EXT_LIBDIR"
# Required header and library for dmalloc
# We could also -DFINI_DMALLOC=0, but instead we turn off -Werror
# For the threads tests to run, the number below should be set between 5 and 30
# This asks dmalloc to wait for the thread manager to start up
# These variables were generated using "dmalloc -o <number>", 
# then modified to correctly parse in bash
# On my system, lockon 3 passes, but 2 fails then hangs, and 0 goes recursive
#DMALLOC_OPTIONS="lockon=3"
#export DMALLOC_OPTIONS
# Set the OS X library path to include the dmalloc library
#export DYLD_FALLBACK_LIBRARY_PATH=$DYLD_FALLBACK_LIBRARY_PATH:$EXT_LIBDIR

# On my system, libevent and (the working version of) openssl 
# are in a non-system directory
# We also use dmalloc across all builds to catch memory errors early
# We disable documentation and dependency tracking to speed up the builds

#--with-dmalloc

# we can also use --analyze for the clang static analyser
# -ftrapv causes the sscanf test to crash / fail
# as do -fsanitize=undefined-trap -fsanitize-undefined-trap-on-error
# -fbounds-checking causes lots of incorrect deprecation warnings
# -fsanitize-memory-track-origins increases memory usage, and causes warnings
# PARANOIA activates extra asserts
CLANG="clang -g -Wall -Wextra -DPARANOIA -fstack-protector -fsanitize=undefined-trap -fsanitize-undefined-trap-on-error -ftrapv"
CC="$CLANG"

CC_OPTS="--with-libevent-dir=$EXT_LIBDIR --with-openssl-dir=$EXT_LIBDIR CPPFLAGS=$CPPFLAGS --disable-asciidoc --disable-dependency-tracking --enable-gcc-warnings-advisory"
MAKE="make -j4"

date

# If any of these builds fail, we want to stop there and fix the error

# Enable extras, disable security, use (older) system libraries
# We could also use libnatpmp if available: --enable-nat-pmp
CC="$CLANG $O_FAST -flto" \
LDFLAGS_FLTO="$LDFLAGS -flto" \
$MAKE clean \
&& \
./configure --prefix=$PREFIX_BASE/tor-features-install CC="$CC" $CC_OPTS --enable-instrument-downloads --enable-upnp --with-libminiupnpc-dir=$EXT_LIBDIR --disable-gcc-hardening --disable-linker-hardening LDFLAGS="$LDFLAGS_FLTO" \
&& $MAKE \
&& $MAKE test \
&& $MAKE install \
&& date || exit

# Use defaults wherever possible, including (older) system libraries
CC="$CLANG $O_SIZE" \
$MAKE clean \
&& \
./configure --prefix=$PREFIX_BASE/tor-default-install CC="$CC" $CC_OPTS LDFLAGS="$LDFLAGS" \
&& $MAKE \
&& $MAKE test \
&& $MAKE install \
&& date || exit

# Disable extras, options, enable security, use (newer) libraries, 
# avoid optimising too much
CC="$CLANG $O_MIN -fstrict-aliasing -Wstrict-aliasing" \
$MAKE clean \
&& \
./configure --prefix=$PREFIX_BASE/tor-harden-install CC="$CC" $CC_OPTS --disable-curve25519 --disable-transparent --disable-largefile --enable-expensive-hardening --with-openssl-dir=$EXT_LIBDIR --with-zlib-dir=$EXT_LIBDIR LDFLAGS="$LDFLAGS" \
&& $MAKE \
&& $MAKE test \
&& $MAKE install \
&& date || exit

$MAKE clean

date
