package lfcrypt

import (
	"errors"
)

// TODO(pquerna): convert all errors to a type that containers the reader or writer offsets.

var ErrUnknownCipher = errors.New("lfcrypt: Unknown cipher type in header")
var ErrShortWrite = errors.New("lfcrypt: Short write")
var ErrShortRead = errors.New("lfcrypt: Short read")
var ErrShortRandRead = errors.New("lfcrypt: rand.Read returned with less than the requested data")
var ErrSealedBufferTooLarge = errors.New("lfcrypt: Sealed buffer came back larger than 2^16")
var ErrMetadataTooLarge = errors.New("lfcrypt: Metadata header is larger than 2^16")
var ErrUnknownHeader = errors.New("lfcrypt: Unknown header in encrypted file.")
var ErrCounterMismatch = errors.New("lfcrypt: Counter mismatch in data block")
var ErrTrailingHMACMismatch = errors.New("lfcrypt: File trailing HMAC failed.")
var ErrNoMatchingKey = errors.New("lfcrypt: No valid key for decryption")
