package lfcrypt

import (
	"bytes"
	"testing"
)

var dummyKey = []byte("hellohelloworld1hellohelloworld1hellohelloworld1hellohelloworld1")
var dummyKey2 = []byte("hellohelloworld1hellohelloworld1hellohelloworld1hellohelloworld2")

func TestRoundTrip(t *testing.T) {
	src := bytes.NewReader([]byte("hello world"))
	dst := &bytes.Buffer{}
	roundtrip := &bytes.Buffer{}

	ec, err := NewAES256SHA512(dummyKey)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	err = ec.Encrypt(src, dst)

	if err != nil {
		t.Fatalf("error: %v", err)
	}

	enreader := bytes.NewReader(dst.Bytes())

	err = ec.Decrypt(enreader, roundtrip)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	st := roundtrip.String()
	if st != "hello world" {
		t.Fatal("Failed round trip.")
	}
}

func TestTampered(t *testing.T) {
	src := bytes.NewReader([]byte("hello world"))
	dst := &bytes.Buffer{}
	roundtrip := &bytes.Buffer{}

	ec, err := NewAES256SHA512(dummyKey)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	err = ec.Encrypt(src, dst)

	if err != nil {
		t.Fatalf("error: %v", err)
	}

	b := dst.Bytes()
	b[43] += 1

	enreader := bytes.NewReader(b)
	err = ec.Decrypt(enreader, roundtrip)
	if err != nil {
		return
	}
	t.Fatalf("Missing error from tampered data: enreader:%v", enreader)
}

func roundTripLargeSize(n int, t *testing.T) {
	srfbuf := make([]byte, n)
	src := bytes.NewReader(srfbuf)
	dst := &bytes.Buffer{}
	roundtrip := &bytes.Buffer{}

	ec, err := NewAES256SHA512(dummyKey)
	if err != nil {
		t.Fatalf("error: n=%v %v", n, err)
	}

	err = ec.Encrypt(src, dst)

	if err != nil {
		t.Fatalf("error: n=%v %v", n, err)
	}

	enreader := bytes.NewReader(dst.Bytes())

	err = ec.Decrypt(enreader, roundtrip)
	if err != nil {
		t.Fatalf("error: n=%v %v", n, err)
	}

	if bytes.Compare(roundtrip.Bytes(), srfbuf) != 0 {
		t.Fatalf("error: n=%v Failed round trip: %s", n, err)
	}
}

func TestRoundTripLarge(t *testing.T) {
	roundTripLargeSize(1000, t)
	roundTripLargeSize(10000*99, t)
	roundTripLargeSize((2^16)+1, t)
	roundTripLargeSize((2^16)-1, t)
}

func TestDiffKey(t *testing.T) {
	src := bytes.NewReader([]byte("hello world"))
	dst := &bytes.Buffer{}
	roundtrip := &bytes.Buffer{}

	ec, err := NewAES256SHA512(dummyKey)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	err = ec.Encrypt(src, dst)

	if err != nil {
		t.Fatalf("error: %v", err)
	}

	ec2, err := NewAES256SHA512(dummyKey2)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	enreader := bytes.NewReader(dst.Bytes())

	err = ec2.Decrypt(enreader, roundtrip)
	if err != nil {
		return
	}
	t.Fatalf("Missing error from different key data: enreader:%v", enreader)
}

func TestReadKeyId(t *testing.T) {
	src := bytes.NewReader([]byte("hello world"))
	dst := &bytes.Buffer{}

	ec, err := NewAES256SHA512(dummyKey)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	err = ec.Encrypt(src, dst)

	if err != nil {
		t.Fatalf("error: %v", err)
	}

	enreader := bytes.NewReader(dst.Bytes())
	keyid, err := ReadKeyId(enreader)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	dummy := ComputeKeyId(dummyKey)
	if keyid != dummy {
		t.Fatalf("error: %v != dummy %v", keyid, dummy)
	}

	dummy2 := ComputeKeyId(dummyKey2)
	if keyid == dummy2 {
		t.Fatalf("error: %v == dummy2 %v", keyid, dummy2)
	}
}

func TestVerify(t *testing.T) {
	src := bytes.NewReader([]byte("hello world"))
	dst := &bytes.Buffer{}

	ec, err := NewAES256SHA512(dummyKey)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	err = ec.Encrypt(src, dst)

	if err != nil {
		t.Fatalf("error: %v", err)
	}

	enreader := bytes.NewReader(dst.Bytes())
	err = ec.Verify(enreader)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	ec2, err := NewAES256SHA512(dummyKey2)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	err = ec2.Verify(enreader)
	if err != nil {
		return
	}
	t.Fatalf("Missing error from different key data: enreader:%v", enreader)

}
