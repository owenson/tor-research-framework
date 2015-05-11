#!/bin/bash

# Run the tor "features" target in cache-only mode
#TOR=/test/tor/tor-features-install/bin/tor
TOR=/Users/twilsonb/Library/Developer/Xcode/DerivedData/tor-dwffosaqftyouufwjtqkiwgynlvd/Build/Products/Debug/tor
CONTROL=/test/tor/vidalia/build/src/vidalia/Vidalia.app/Contents/MacOS/Vidalia
LOG_LEVEL=info
DATA_DIR=/test/tor/tor-features-data

# For dmalloc to avoid threading conflicts, 
# the number below should be set between 5 and 30
# This asks dmalloc to wait for the thread manager to start up
# These variables were generated using "dmalloc -o <number>", 
# then modified to correctly parse in bash
# On my system, lockon 3 passes, but 2 fails then hangs, and 0 goes recursive
#DMALLOC_OPTIONS="lockon=3"
#export DMALLOC_OPTIONS
# Set the OS X library path to include the dmalloc library
#EXT_LIBDIR=$HOME/tor/external/lib
#export DYLD_FALLBACK_LIBRARY_PATH=$DYLD_FALLBACK_LIBRARY_PATH:$EXT_LIBDIR


date
$CONTROL --datadir $DATA_DIR --logfile $DATA_DIR/vidalia.$LOG_LEVEL.log --loglevel $LOG_LEVEL &
$TOR -f $DATA_DIR/torrc.cache_only --DataDirectory $DATA_DIR
