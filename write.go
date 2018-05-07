package lfcrypt

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"hash"
	"io"
	"io/ioutil"
)

//
// Encrypts an cleartext input Reader.  Uses chunks of AEAD data, with a header, and trailing hash block.
//
// File Format:
//
// Header: 12 bytes for version and cipher identification:
//		"lfcrypt0":
//		Cipher index (BigEndian.PutUint32):
//				1: AEAD_AES_512_CBC_HMAC_SHA_512
// Header: Metadata
//		Length (BigEndian.PutUint16)
//		JSON data:
//		{
//			key_id: uint32(SECRET_KEY_ID)
//		}
//
// Data block(s):
//		4-byte counter (BigEndian.PutUint32).  Must start at zero and increment by 1 for each chunk.
// 		2-bytes chunk size. (BigEndian.PutUint16)
// 		AEAD encrypted data. (up to `chunkSize`)
//
// Trailing hash block:
// 		0 length data block, followed by:
//		mac []byte: 64 byte HMAC_SHA512(secret) of file's contents, excluding the HMAC block itself.
type writeStream struct {
	cipher  cipher.AEAD
	key     keyId
	r       io.Reader
	w       io.Writer
	counter uint32
	buf     [chunkSize]byte
	nonce   []byte
	enbuf   []byte
	buf4    [4]byte
	buf2    [2]byte
	mac     hash.Hash
}

func (es *writeStream) writeHeader(cipher uint32) error {
	n, err := io.WriteString(es.w, headerStr)
	es.mac.Write([]byte(headerStr))
	if err != nil {
		return err
	}
	if n != len(headerStr) {
		return ErrShortWrite
	}

	binary.BigEndian.PutUint32(es.buf4[:], cipher)
	n, err = es.w.Write(es.buf4[:])
	es.mac.Write(es.buf4[:])
	if err != nil {
		return err
	}
	if n != len(es.buf4) {
		return ErrShortWrite
	}

	keydata, err := json.Marshal(&es.key)
	if err != nil {
		return err
	}

	if len(keydata) > int(maxUint16) {
		return ErrMetadataTooLarge
	}

	keylen := uint16(len(keydata))
	binary.BigEndian.PutUint16(es.buf2[:], keylen)
	n, err = es.w.Write(es.buf2[:])
	es.mac.Write(es.buf2[:])
	if err != nil {
		return err
	}
	if n != len(es.buf2) {
		return ErrShortWrite
	}

	n, err = es.w.Write(keydata)
	es.mac.Write(keydata)
	if err != nil {
		return err
	}
	if n != len(keydata) {
		return ErrShortWrite
	}

	return nil
}

func (es *writeStream) writeCounter() error {
	binary.BigEndian.PutUint32(es.buf4[:], es.counter)
	n, err := es.w.Write(es.buf4[:])
	es.mac.Write(es.buf4[:])
	if err != nil {
		return err
	}
	if n != len(es.buf4) {
		return ErrShortWrite
	}
	es.counter++
	return nil
}

func (es *writeStream) refreshNonce() error {
	n, err := rand.Read(es.nonce)
	if err != nil {
		return err
	}
	if n != len(es.nonce) {
		return ErrShortRandRead
	}
	return nil
}

func (es *writeStream) writeSealedData(nr int) error {
	es.enbuf = es.enbuf[0:0]
	es.enbuf = es.cipher.Seal(es.enbuf, es.nonce, es.buf[0:nr], []byte{})
	if len(es.enbuf) > int(maxUint16) {
		return ErrSealedBufferTooLarge
	}

	binary.BigEndian.PutUint16(es.buf2[:], uint16(len(es.enbuf)))
	n, err := es.w.Write(es.buf2[:])
	es.mac.Write(es.buf2[:])
	if err != nil {
		return err
	}
	if n != len(es.buf2) {
		return ErrShortWrite
	}

	n, err = es.w.Write(es.enbuf)
	es.mac.Write(es.enbuf)
	if err != nil {
		return err
	}
	if n != len(es.enbuf) {
		return ErrShortWrite
	}
	return nil
}

func (es *writeStream) writeEmptyData() error {
	binary.BigEndian.PutUint16(es.buf2[:], uint16(0))
	n, err := es.w.Write(es.buf2[:])
	es.mac.Write(es.buf2[:])
	if err != nil {
		return err
	}
	if n != len(es.buf2) {
		return ErrShortWrite
	}
	return nil
}

func (es *writeStream) writeTrailingMAC() error {
	outmac := es.mac.Sum(nil)
	n, err := es.w.Write(outmac)
	if err != nil {
		return err
	}

	if n != len(outmac) {
		return ErrShortWrite
	}

	return nil
}

func (es *writeStream) copy() error {
	var err error

	for {
		nr, readerr := es.r.Read(es.buf[:])

		if nr > 0 {
			err = es.refreshNonce()
			if err != nil {
				return err
			}

			err = es.writeCounter()
			if err != nil {
				return err
			}

			err = es.writeSealedData(nr)
			if err != nil {
				return err
			}
		}

		// you are allowed to both return >0 bytes *and* EOF in the same Read() call. FML.
		if readerr == io.EOF {
			err = es.writeCounter()
			if err != nil {
				return err
			}
			err = es.writeEmptyData()
			if err != nil {
				return err
			}
			break
		} else if readerr != nil {
			return readerr
		}
	}

	err = es.writeTrailingMAC()
	if err != nil {
		return err
	}
	return nil
}

func (e *etmCryptor) Verify(r io.ReadSeeker) error {
	err := e.Decrypt(r, ioutil.Discard)
	if err != nil {
		return err
	}
	_, err = r.Seek(0, 0)
	if err != nil {
		return err
	}
	return nil
}

func (e *etmCryptor) Encrypt(r io.Reader, w io.Writer) error {
	stream := writeStream{
		key:     keyId{e.keyid},
		cipher:  e.c,
		r:       r,
		w:       w,
		counter: 0,
		nonce:   make([]byte, e.c.NonceSize()),
		enbuf:   make([]byte, chunkSize+e.c.Overhead()),
		mac:     e.newTrailerHMAC(),
	}

	s := uint32(0)
	switch e.ctype {
	case AEAD_AES_256_CBC_HMAC_SHA_512:
		s = AEAD_AES_256_CBC_HMAC_SHA_512_ID
	default:
		return ErrUnknownCipher
	}

	err := stream.writeHeader(s)
	if err != nil {
		return err
	}

	err = stream.copy()
	if err != nil {
		return err
	}

	return nil
}
