#!/bin/sh
# (c) Ain Ghazal 2022
# this file converts an inline openvpn config file into
# a standalone config plus separate files for the ca.crt,
# cert.pem and key.pem.

FILE=$1
tail=0

# first lets extract the inline blocks
# ca block
tag=ca
f=ca.crt
sed -n "/<$tag>/,/<\/$tag>/p" $FILE > $f
n=$(wc -l $f | cut -f 1 -d ' ')
tail=$(($tail+n))
cat $f | tail -n $(($n-1)) | head -n $(($n-2)) | tee $f

# key block
tag=key
f=key.pem
sed -n "/<$tag>/,/<\/$tag>/p" $FILE > $f
n=$(wc -l $f | cut -f 1 -d ' ')
tail=$(($tail+n))
cat $f | tail -n $(($n-1)) | head -n $(($n-2)) | tee $f

# cert block
tag=cert
f=cert.pem
sed -n "/<$tag>/,/<\/$tag>/p" $FILE > $f
n=$(wc -l $f | cut -f 1 -d ' ')
tail=$(($tail+n))
cat $f | tail -n $(($n-1)) | head -n $(($n-2)) | tee $f

# tls-auth (ignored)
tag=tls-auth
f=ta.pem
sed -n "/<$tag>/,/<\/$tag>/p" $FILE > $f
n=$(wc -l $f | cut -f 1 -d ' ')
echo "lines:::" $n
tail=$(($tail+n))
cat $f | tail -n $(($n-4)) | head -n $(($n-5)) | tee $f

all=$(wc -l $FILE | cut -f -1 -d ' ')
cp $FILE config.bk
head -n $(($all-$tail)) $FILE | tee config

# now enable the paths for ca, cert and key
sed -i "s/;ca ca.crt/ca ca.crt/g" config
sed -i "s/;cert cert.pem/cert cert.pem/g" config
sed -i "s/;key key.pem/key key.pem/g" config
