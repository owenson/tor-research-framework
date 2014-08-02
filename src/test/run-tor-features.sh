#!/bin/bash

# Run the tor "features" target in cache-only mode
TOR=/test/tor/tor-features-install/bin/tor
CONTROL=/test/tor/vidalia/build/src/vidalia/Vidalia.app/Contents/MacOS/Vidalia
LOG_LEVEL=info
DATA_DIR=/test/tor/tor-features-data

date
$CONTROL --datadir $DATA_DIR --logfile $DATA_DIR/vidalia.$LOG_LEVEL.log --loglevel $LOG_LEVEL &
$TOR -f $DATA_DIR/torrc.cache_only --DataDirectory $DATA_DIR
