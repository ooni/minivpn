#!/bin/sh
# (c) Ain Ghazal 2022
# this file converts an inline openvpn config file into
# a standalone config plus separate files for the ca.crt,
# cert.pem and key.pem.

FILE=$1
tail=0

# first lets extract the inline blocks
tag=ca
f=ca.crt
sed -n "/<$tag>/,/<\/$tag>/p" $FILE > $f
n=$(wc -l $f | cut -f 1 -d ' ')
tail=$(($tail+n))
cat $f | tail -n $(($n-1)) | head -n $(($n-2)) | tee $f

tag=key
f=key.pem
sed -n "/<$tag>/,/<\/$tag>/p" $FILE > $f
n=$(wc -l $f | cut -f 1 -d ' ')
tail=$(($tail+n))
cat $f | tail -n $(($n-1)) | head -n $(($n-2)) | tee $f

tag=cert
f=cert.pem
sed -n "/<$tag>/,/<\/$tag>/p" $FILE > $f
n=$(wc -l $f | cut -f 1 -d ' ')
tail=$(($tail+n))
cat $f | tail -n $(($n-1)) | head -n $(($n-2)) | tee $f

all=$(wc -l $FILE | cut -f -1 -d ' ')
cp $FILE config.bk
head -n $(($all-$tail)) $FILE | tee config

# TODO need to ignore the ta key until we do support it...
