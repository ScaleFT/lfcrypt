package lfcrypt

import (
	"crypto"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"hash"

	"github.com/codahale/etm"

	"io"
)

const (
	AEAD_AES_256_CBC_HMAC_SHA_512    = "AEAD_AES_256_CBC_HMAC_SHA_512"
	AEAD_AES_256_CBC_HMAC_SHA_512_ID = uint32(1)
)

type Cryptor interface {
	KeyId() uint32

	Encrypt(r io.Reader, w io.Writer) error

	// Decrypts reader into writer.  May return error after writer is partially written, so be sure to discard
	// the writers data in this case.
	Decrypt(r io.Reader, w io.Writer) error

	// Verify source reader is authenticated and valid.  On success, seeks back to start of file.
	// Returns nil error if input is verified.
	Verify(r io.ReadSeeker) error
}

// NewAES256SHA512 constructs a Cryptor an AEAD construct with AES-256-CBC encryption and SHA-512 MACs
// using a 64-byte secret.
func NewAES256SHA512(secret []byte) (Cryptor, error) {
	e, err := etm.NewAES256SHA512(secret)
	if err != nil {
		return nil, err
	}

	return &etmCryptor{
		keyid:  ComputeKeyId(secret),
		secret: secret,
		c:      e,
		mac:    crypto.SHA512,
		ctype:  AEAD_AES_256_CBC_HMAC_SHA_512,
	}, nil
}

func ComputeKeyId(key []byte) uint32 {
	// Use the first 4 bytes of the sha512 of the key as the id. Keyczar does
	// this using sha1.
	data := sha512.Sum512(key)
	return binary.BigEndian.Uint32(data[0:4])
}

type etmCryptor struct {
	keyid  uint32
	ctype  string
	secret []byte
	mac    crypto.Hash
	c      cipher.AEAD
}

func (e *etmCryptor) KeyId() uint32 {
	return e.keyid
}

func (e *etmCryptor) newTrailerHMAC() hash.Hash {
	return hmac.New(e.mac.New, e.secret)
}
