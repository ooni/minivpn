#!/bin/sh

# Ref:
# - https://pretzelhands.com/posts/command-line-flags

# Usage:
# go test -race -v -coverprofile=coverage.out
# ./go-coverage-check.sh coverage.out 70


PROFILE=$1
THRESHOLD=$2
COVERAGE=$(go tool cover -func=$PROFILE | grep total|awk '{print substr($3, 1, length($3) - 1)}')
echo "$COVERAGE $THRESHOLD" | awk '{if (!($1 >= $2)) { print "Coverage: " $1 "%" ", Expected threshold: " $2 "%"; exit 1 } }'
