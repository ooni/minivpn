#!/bin/sh
set -e
COVDATA=../../coverage/int

#
# Setup
#
rm -rf $COVDATA
mkdir -p $COVDATA

#
# Pass in "-cover" to the script to build for coverage, then
# run with GOCOVERDIR set.
#
go build -cover .
GOCOVERDIR=$COVDATA ./integration

#
# Post-process the resulting profiles.
#
go tool covdata percent -i=$COVDATA

#
# Remove the binary
# 
rm ./integration
