#!/bin/bash

# Run the tor "features" target in cache-only mode
TOR=/test/tor/tor-features-install/bin/tor
DATADIR=/test/tor/tor-features-data

date
$TOR -f $DATADIR/torrc.cache_only --DataDirectory $DATADIR
date
