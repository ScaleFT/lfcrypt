package lfcrypt

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"testing"
)

var dummyKey = []byte("hellohelloworld1hellohelloworld1hellohelloworld1hellohelloworld1")
var dummyKey2 = []byte("hellohelloworld1hellohelloworld1hellohelloworld1hellohelloworld2")
var dummyKey32 = []byte("hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh")

func TestRoundTrip_AES(t *testing.T) {
	ec, err := NewAES256SHA512(dummyKey)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	testRoundTrip(t, ec)
}

func TestRoundTrip_chacha20poly1305(t *testing.T) {
	ec, err := NewCHACHA20POLY1305(dummyKey32)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	testRoundTrip(t, ec)
}

func testRoundTrip(t *testing.T, ec Cryptor) {
	src := bytes.NewReader([]byte("hello world"))
	dst := &bytes.Buffer{}
	roundtrip := &bytes.Buffer{}

	err := ec.Encrypt(src, dst)
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

func TestTampered_AES(t *testing.T) {
	ec, err := NewAES256SHA512(dummyKey)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	testTampered(t, ec)
}

func TestTampered_chacha20poly1305(t *testing.T) {
	ec, err := NewCHACHA20POLY1305(dummyKey32)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	testTampered(t, ec)
}

func testTampered(t *testing.T, ec Cryptor) {
	src := bytes.NewReader([]byte("hello world"))
	dst := &bytes.Buffer{}
	roundtrip := &bytes.Buffer{}

	err := ec.Encrypt(src, dst)
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

func TestRoundTripLarge_AES(t *testing.T) {
	ec, err := NewAES256SHA512(dummyKey)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	testRoundTripLarge(t, ec)
}
func TestRoundTripLarge_chacha20poly1305(t *testing.T) {
	ec, err := NewCHACHA20POLY1305(dummyKey32)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	testRoundTripLarge(t, ec)
}

func testRoundTripLarge(t *testing.T, ec Cryptor) {
	roundTripLargeSize(1000, t, ec)
	roundTripLargeSize(10000*99, t, ec)
	roundTripLargeSize((2^16)+1, t, ec)
	roundTripLargeSize((2^16)-1, t, ec)
}

func roundTripLargeSize(n int, t *testing.T, ec Cryptor) {
	srfbuf := make([]byte, n)
	src := bytes.NewReader(srfbuf)
	dst := &bytes.Buffer{}
	roundtrip := &bytes.Buffer{}

	err := ec.Encrypt(src, dst)
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

func TestDiffKey_AES(t *testing.T) {
	ec, err := NewAES256SHA512(dummyKey)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	ec2, err := NewAES256SHA512(dummyKey2)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	testDiffKey(t, ec, ec2)
}

func TestDiffKey_chacha20poly1305(t *testing.T) {
	ec, err := NewCHACHA20POLY1305(dummyKey32)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	ec2, err := NewCHACHA20POLY1305(dummyKey2[0:32])
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	testDiffKey(t, ec, ec2)
}

func testDiffKey(t *testing.T, ec Cryptor, ec2 Cryptor) {
	src := bytes.NewReader([]byte("hello world"))
	dst := &bytes.Buffer{}
	roundtrip := &bytes.Buffer{}

	err := ec.Encrypt(src, dst)
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

func TestBrokenHeader(t *testing.T) {
	ec, err := NewAES256SHA512(dummyKey)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	src := bytes.NewReader([]byte("hello world"))
	dst := &bytes.Buffer{}
	err = ec.Decrypt(src, dst)
	if err == nil {
		t.Fatalf("expected error: %v", err)
	}

	src = bytes.NewReader([]byte("lfcrypt0AAAA"))
	dst = &bytes.Buffer{}
	err = ec.Decrypt(src, dst)
	if err != ErrUnknownCipher {
		t.Fatalf("expected ErrUnknownCipher error: %v", err)
	}

	src = bytes.NewReader([]byte("lfcrypt0" + "\x00\x00" + "\x02" + "{}"))
	dst = &bytes.Buffer{}
	err = ec.Decrypt(src, dst)
	if err != ErrUnknownCipher {
		t.Fatalf("expected ErrUnknownCipher error: %v", err)
	}

	var buf4 [4]byte
	var buf2 [2]byte
	binary.BigEndian.PutUint32(buf4[:], AEAD_AES_256_CBC_HMAC_SHA_512_ID)
	binary.BigEndian.PutUint16(buf2[:], 2)

	src = bytes.NewReader([]byte("lfcrypt0" + string(buf4[:]) + string(buf2[:]) + "{}"))
	dst = &bytes.Buffer{}
	err = ec.Decrypt(src, dst)
	if err != ErrNoMatchingKey {
		t.Fatalf("expected ErrNoMatchingKey error: %v", err)
	}

	keydata, err := json.Marshal(&keyId{
		KeyID: 42,
	})
	if err != nil {
		t.Fatalf("json error: %v", err)
	}
	binary.BigEndian.PutUint16(buf2[:], uint16(len(keydata)))

	src = bytes.NewReader([]byte("lfcrypt0" + string(buf4[:]) + string(buf2[:]) + string(keydata)))
	kid, err := ReadKeyId(src)
	if err != nil {
		t.Fatalf("json error: %v", err)
	}
	if kid != 42 {
		t.Fatalf("unexpected key id: %v", kid)
	}
}

func TestVerify_AES(t *testing.T) {
	ec, err := NewAES256SHA512(dummyKey)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	testVerify(t, ec)
}

func TestVerify_chacha20poly1305(t *testing.T) {
	ec, err := NewCHACHA20POLY1305(dummyKey[0:32])
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	testVerify(t, ec)
}

func testVerify(t *testing.T, ec Cryptor) {
	src := bytes.NewReader([]byte("hello world"))
	dst := &bytes.Buffer{}

	err := ec.Encrypt(src, dst)

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
