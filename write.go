package lfcrypt

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"hash"
	"io"
)

type writeStream struct {
	cipher     cipher.AEAD
	cipherType uint32
	key        keyId
	r          io.Reader
	w          io.Writer
	counter    uint32
	buf        [chunkSize]byte
	nonce      []byte
	enbuf      []byte
	buf4       [4]byte
	buf2       [2]byte
	mac        hash.Hash
}

// Encrypt writes the contents of r into a w using lfcrypt encrypted format.
func (e *etmCryptor) Encrypt(r io.Reader, w io.Writer) error {
	stream, err := e.newWriteStream(r, w)
	if err != nil {
		return err
	}
	defer e.writeBufferPool.Put(stream.enbuf)

	err = stream.writeHeader()
	if err != nil {
		return err
	}

	err = stream.copy()
	if err != nil {
		return err
	}

	return nil
}

func (e *etmCryptor) newWriteStream(r io.Reader, w io.Writer) (*writeStream, error) {
	stream := &writeStream{
		key:        keyId{e.keyid},
		cipherType: e.cipherType,
		cipher:     e.c,
		r:          r,
		w:          w,
		counter:    0,
		nonce:      make([]byte, e.c.NonceSize()),
		enbuf:      e.writeBufferPool.Get().([]byte),
		mac:        e.newTrailerHMAC(),
	}

	return stream, nil
}

func (es *writeStream) writeHeader() error {
	n, err := io.WriteString(es.w, headerStr)
	es.mac.Write([]byte(headerStr))
	if err != nil {
		return err
	}
	if n != len(headerStr) {
		return ErrShortWrite
	}

	binary.BigEndian.PutUint32(es.buf4[:], uint32(es.cipherType))
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

func (es *writeStream) writeCounter() (uint32, error) {
	count := es.counter
	binary.BigEndian.PutUint32(es.buf4[:], count)
	n, err := es.w.Write(es.buf4[:])
	es.mac.Write(es.buf4[:])
	if err != nil {
		return 0, err
	}
	if n != len(es.buf4) {
		return 0, ErrShortWrite
	}
	es.counter++
	return count, nil
}

func (es *writeStream) refreshNonce(counter uint32) error {
	binary.BigEndian.PutUint32(es.buf4[:], counter)
	n, err := rand.Read(es.nonce[:])
	if err != nil {
		return err
	}
	if n != len(es.nonce) {
		return ErrShortRandRead
	}

	for i := 0; i < len(es.nonce); i++ {
		es.nonce[i] = es.nonce[i] ^ es.buf4[i%4]
	}
	return nil
}

func (es *writeStream) writeSealedData(nr int, counter uint32) error {
	writeNonce := false
	switch es.cipherType {
	case AEAD_AES_256_CBC_HMAC_SHA_512_ID:
		break
	case AEAD_CHACHA20_POLY1305_HMAC_SHA512_ID:
		writeNonce = true
		break
	default:
		return ErrUnknownCipher
	}

	err := es.refreshNonce(counter)
	if err != nil {
		return err
	}

	es.enbuf = es.enbuf[0:0]
	es.enbuf = es.cipher.Seal(es.enbuf, es.nonce, es.buf[0:nr], []byte{})
	if len(es.enbuf) > int(maxUint16) {
		return ErrSealedBufferTooLarge
	}

	enlen := uint16(len(es.enbuf))

	if writeNonce {
		enlen += uint16(len(es.nonce))
	}

	binary.BigEndian.PutUint16(es.buf2[:], enlen)
	n, err := es.w.Write(es.buf2[:])
	es.mac.Write(es.buf2[:])
	if err != nil {
		return err
	}
	if n != len(es.buf2) {
		return ErrShortWrite
	}

	if writeNonce {
		n, err = es.w.Write(es.nonce)
		es.mac.Write(es.nonce)
		if err != nil {
			return err
		}
		if n != len(es.nonce) {
			return ErrShortWrite
		}
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
			counter, err := es.writeCounter()
			if err != nil {
				return err
			}

			err = es.writeSealedData(nr, counter)
			if err != nil {
				return err
			}
		}

		// you are allowed to both return >0 bytes *and* EOF in the same Read() call. FML.
		if readerr == io.EOF {
			_, err = es.writeCounter()
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
