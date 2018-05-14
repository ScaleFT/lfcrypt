# lfcrypt

[![GoDoc](https://godoc.org/github.com/ScaleFT/lfcrypt?status.svg)](https://godoc.org/github.com/ScaleFT/lfcrypt)
[![Build Status](https://travis-ci.org/ScaleFT/lfcrypt.svg?branch=master)](https://travis-ci.org/ScaleFT/lfcrypt)

`lfcrypt` is a Go library for the symmetric encryption of large files.  This includes streaming reading and writing, and a trailer section ensuring a complete file.

The file extension `.lfenc` is used for streams encrypted with this format.

## Concepts

[Encrypting streams](https://www.imperialviolet.org/2014/06/27/streamingencryption.html) by Adam Langley outlines many of the issues with encrypting streams or large files.

### Avoiding Output without verification

GPG will decrypt a stream and output it before it has been validated, because the HMAC of the file is at the very end.

In `lfcrypt`, the stream is authenticated incrementally. Contents of the stream could be truncated by an attacker, and in this case an error is returned by the API, but no cleartext is ever emitted that was not authenticated.

### Avoiding Chunking Issues

When designing a stream format, you must ensure that chunks in the stream are not reordered, dropped, or truncated.  `lfcrypt` prevents this by requiring an incrementing `.counter` field for every data chunk.

### Supporting Seeking

Because each data chunk in `lfcrypt` is it's own independent AEAD construct with a local IV determined by the `.cipher_ident`, seeking without necessarily storing the entire file in memory or incremental MACs is possible.

## Stream Format

### Header chunk

12 bytes for version and cipher identification:

- `.version`: 8 byte string. Static string: `lfcrypt0`
- `.cipher_ident`: 4 bytes encoded in big endian (`BigEndian.PutUint32`):
    - `1`: `AEAD_AES_256_CBC_HMAC_SHA_512`
    - `2`: `AEAD_CHACHA20_POLY1305_HMAC_SHA512`

### Metadata chunk

- `.length`: 2 bytes encoded in big endian (`BigEndian.PutUint16`)
- `.metadata`: JSON data of `.length`. Example:

```
{
    key_id: 1234,
}
```

`key_id` can be used by readers to find a secret-key by unique ID.  Other JSON fields are ignored at this time,
and implementations should ignore any unknown fields.

### Data chunk

- `.counter`: 4 bytes encoded in big endian (`BigEndian.PutUint32`). Must start at zero and increment by 1 for each chunk in the stream.
- `.length`: 2 bytes encoded in big endian (`BigEndian.PutUint16`). Must be >= 1, See trailing chunk for behavoir of a zero byte data chunk
- `.encrypted_data`:  Encrypted data of `.length`.

Based on `.cipher_id`, `.encrypted_data` may contain additional interior fields:

- `AEAD_AES_256_CBC_HMAC_SHA_512`: Contains a [draft-mcgrew-aead-aes-cbc-hmac-sha2-05.txt](https://tools.ietf.org/html/draft-mcgrew-aead-aes-cbc-hmac-sha2-05#section-2.1) formatted block.

- `AEAD_CHACHA20_POLY1305_HMAC_SHA512`:
  - `.nonce`: 12 bytes of random nonce. The 4 bytes of `.counter` has been XOR'ed into the random nonce.
  - `.data`: Remaining encrypted data.

### Trailing MAC chunk:
- `.mac`: Variable length mac based on `.cipher_ident`:
  - `AEAD_AES_256_CBC_HMAC_SHA_512`: []byte: 64 byte HMAC_SHA512(secret) of all previous chunks, excluding the HMAC block itself.
  - `AEAD_CHACHA20_POLY1305_HMAC_SHA512`: []byte: 64 byte HMAC_SHA512(secret) of all previous chunks, excluding the HMAC block itself.

# License

`lfcrypt` is licensed under the Apache License Version 2.0. See the [LICENSE file](./LICENSE) for details.
