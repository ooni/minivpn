package vpn

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"hash"
)

// prf function is used to derive master and client keys
func prf(secret, label, clientSeed, serverSeed, clientSid, serverSid []byte, olen int) []byte {
	seed := append(clientSeed, serverSeed...)
	if len(clientSid) != 0 {
		seed = append(seed, clientSid...)
	}
	if len(serverSid) != 0 {
		seed = append(seed, serverSid...)
	}
	result := make([]byte, olen)
	return prf10(result, secret, label, seed)
}

// Code below is taken from crypto/tls/prf.go
// Copyright 2009 The Go Authors. All rights reserved.
// prf10 implements the TLS 1.0 pseudo-random function, as defined in RFC 2246, Section 5.

func prf10(result, secret, label, seed []byte) []byte {
	hashSHA1 := sha1.New
	hashMD5 := md5.New

	labelAndSeed := make([]byte, len(label)+len(seed))
	copy(labelAndSeed, label)
	copy(labelAndSeed[len(label):], seed)

	s1, s2 := splitPreMasterSecret(secret)
	pHash(result, s1, labelAndSeed, hashMD5)
	result2 := make([]byte, len(result))
	pHash(result2, s2, labelAndSeed, hashSHA1)
	for i, b := range result2 {
		result[i] ^= b
	}
	return result
}

// Split a premaster secret in two as specified in RFC 4346, Section 5.
func splitPreMasterSecret(secret []byte) (s1, s2 []byte) {
	s1 = secret[0 : (len(secret)+1)/2]
	s2 = secret[len(secret)/2:]
	return

}

// pHash implements the P_hash function, as defined in RFC 4346, Section 5.
func pHash(result, secret, seed []byte, hash func() hash.Hash) {
	h := hmac.New(hash, secret)
	h.Write(seed)
	a := h.Sum(nil)
	j := 0
	for j < len(result) {
		h.Reset()
		h.Write(a)
		h.Write(seed)
		b := h.Sum(nil)
		copy(result[j:], b)
		j += len(b)
		h.Reset()
		h.Write(a)
		a = h.Sum(nil)
	}
}
