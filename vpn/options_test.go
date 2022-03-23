package vpn

// this file exercises the options parsing.

import (
	"fmt"
	"os"
	fp "path/filepath"
	"testing"
)

func writeDummyCertFiles(d string) {
	os.WriteFile(fp.Join(d, "ca.crt"), []byte("dummy"), 0600)
	os.WriteFile(fp.Join(d, "cert.pem"), []byte("dummy"), 0600)
	os.WriteFile(fp.Join(d, "key.pem"), []byte("dummy"), 0600)
}

func TestGetOptionsFromLines(t *testing.T) {
	d := t.TempDir()
	l := []string{
		"remote 0.0.0.0 1194",
		"cipher AES-256-GCM",
		"auth SHA512",
		"ca ca.crt",
		"cert cert.pem",
		"key cert.pem",
	}
	writeDummyCertFiles(d)
	o, err := getOptionsFromLines(l, d)
	if err != nil {
		fmt.Println("error:", err)
		t.Errorf("Good options should not fail")
	}
	if o.Cipher != "AES-256-GCM" {
		t.Errorf("Cipher not what expected")
	}
	if o.Auth != "SHA512" {
		t.Errorf("Auth not what expected")
	}
}

func TestGetOptionsFromLinesNoFiles(t *testing.T) {
	d := t.TempDir()
	l := []string{
		"ca ca.crt",
	}
	_, err := getOptionsFromLines(l, d)
	if err == nil {
		t.Errorf("Should fail if no files provided")
	}
}

func TestGetOptionsNoCompression(t *testing.T) {
	d := t.TempDir()
	l := []string{
		"compress",
	}
	// should fail if no certs
	// writeDummyCertFiles(d)
	o, err := getOptionsFromLines(l, d)
	if err != nil {
		t.Errorf("Should not fail: compress")
	}
	if o.Compress != "empty" {
		t.Errorf("Expected compress==empty")
	}
}

func TestGetOptionsCompressionStub(t *testing.T) {
	d := t.TempDir()
	l := []string{
		"compress stub",
	}
	// should fail if no certs
	// writeDummyCertFiles(d)
	o, err := getOptionsFromLines(l, d)
	if err != nil {
		t.Errorf("Should not fail: compress stub")
	}
	if o.Compress != "stub" {
		t.Errorf("expected compress==stub")
	}
}

func TestGetOptionsCompressionBad(t *testing.T) {
	d := t.TempDir()
	l := []string{
		"compress foo",
	}
	// should fail if no certs
	// writeDummyCertFiles(d)
	_, err := getOptionsFromLines(l, d)
	if err == nil {
		t.Errorf("Unknown compress: should fail")
	}
}

func TestGetOptionsCompressLZO(t *testing.T) {
	d := t.TempDir()
	l := []string{
		"comp-lzo no",
	}
	// should fail if no certs
	// writeDummyCertFiles(d)
	o, err := getOptionsFromLines(l, d)
	if err != nil {
		t.Errorf("Should not fail: lzo-comp no")
	}
	if o.Compress != "lzo-no" {
		t.Errorf("expected compress=lzo-no")
	}
}

func TestGetOptionsBadRemote(t *testing.T) {
	d := t.TempDir()
	l := []string{
		"remote",
	}
	// should fail if no certs
	// writeDummyCertFiles(d)
	_, err := getOptionsFromLines(l, d)
	if err == nil {
		t.Errorf("Should fail: malformed remote")
	}
}

func TestGetOptionsBadCipher(t *testing.T) {
	d := t.TempDir()
	l := []string{
		"cipher",
	}
	// should fail if no certs
	// writeDummyCertFiles(d)
	_, err := getOptionsFromLines(l, d)
	if err == nil {
		t.Errorf("Should fail: malformed cipher")
	}
	l = []string{
		"cipher AES-111-CBC",
	}
	_, err = getOptionsFromLines(l, d)
	if err == nil {
		t.Errorf("Should fail: bad cipher")
	}
}

func TestGetOptionsComment(t *testing.T) {
	d := t.TempDir()
	l := []string{
		"cipher AES-256-GCM",
		"#cipher AES-128-GCM",
	}
	// should fail if no certs
	// writeDummyCertFiles(d)
	o, err := getOptionsFromLines(l, d)
	if err != nil {
		t.Errorf("Should not fail: commented line")
	}
	if o.Cipher != "AES-256-GCM" {
		t.Errorf("Expected cipher: AES-256-GCM")
	}
}
