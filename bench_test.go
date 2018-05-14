package lfcrypt

import (
	"bytes"
	"io"
	"io/ioutil"
	"testing"
)

func BenchmarkDecryptSmall_AES(b *testing.B) {
	ec, err := NewAES256SHA512(dummyKey)
	if err != nil {
		b.Fatalf("error: %v", err)
	}
	src := bytes.NewReader([]byte("hello world"))
	benchDecrypt(b, ec, src)
}

func BenchmarkDecryptSmall_chacha20poly1305(b *testing.B) {
	ec, err := NewCHACHA20POLY1305(dummyKey32)
	if err != nil {
		b.Fatalf("error: %v", err)
	}
	src := bytes.NewReader([]byte("hello world"))
	benchDecrypt(b, ec, src)
}

func BenchmarkEncryptSmall_AES(b *testing.B) {
	ec, err := NewAES256SHA512(dummyKey)
	if err != nil {
		b.Fatalf("error: %v", err)
	}
	src := bytes.NewReader([]byte("hello world"))
	benchEncrypt(b, ec, src)
}

func BenchmarkEncryptSmall_chacha20poly1305(b *testing.B) {
	ec, err := NewCHACHA20POLY1305(dummyKey32)
	if err != nil {
		b.Fatalf("error: %v", err)
	}
	src := bytes.NewReader([]byte("hello world"))
	benchEncrypt(b, ec, src)
}

func BenchmarkEncryptStream_AES(b *testing.B) {
	ec, err := NewAES256SHA512(dummyKey)
	if err != nil {
		b.Fatalf("error: %v", err)
	}
	src := bytes.NewReader([]byte("hello world"))
	benchEncryptStream(b, ec, src)
}

func BenchmarkEncryptStream_chacha20poly1305(b *testing.B) {
	ec, err := NewCHACHA20POLY1305(dummyKey32)
	if err != nil {
		b.Fatalf("error: %v", err)
	}
	src := bytes.NewReader([]byte("hello world"))
	benchEncryptStream(b, ec, src)
}

func benchEncrypt(b *testing.B, ec Cryptor, src io.ReadSeeker) {
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		src.Seek(0, io.SeekStart)
		dst := &bytes.Buffer{}
		err := ec.Encrypt(src, dst)
		if err != nil {
			b.Fatalf("error: %v", err)
		}
	}
}

func benchDecrypt(b *testing.B, ec Cryptor, src io.ReadSeeker) {
	src.Seek(0, io.SeekStart)
	endata := &bytes.Buffer{}
	err := ec.Encrypt(src, endata)
	if err != nil {
		b.Fatalf("error: %v", err)
	}
	enrdr := bytes.NewReader(endata.Bytes())
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		enrdr.Seek(0, io.SeekStart)
		err := ec.Decrypt(enrdr, ioutil.Discard)
		if err != nil {
			b.Fatalf("error: %v", err)
		}
	}
}

type nws interface {
	newWriteStream(r io.Reader, w io.Writer) (*writeStream, error)
}

func benchEncryptStream(b *testing.B, ec Cryptor, src io.ReadSeeker) {
	r, w := io.Pipe()
	ecx := ec.(nws)
	stream, err := ecx.newWriteStream(r, ioutil.Discard)
	if err != nil {
		b.Fatalf("error: %v", err)
	}
	b.ResetTimer()

	errc := make(chan error)
	defer close(errc)

	go func() {
		err := stream.writeHeader()
		if err != nil {
			errc <- err
			return
		}
		err = stream.copy()
		if err != nil {
			errc <- err
			return
		}
		errc <- nil
	}()

	for n := 0; n < b.N; n++ {
		src.Seek(0, io.SeekStart)
		io.Copy(w, src)
	}
	w.Close()

	err = <-errc
	if err != nil {
		b.Fatalf("error in goroutine: %v", err)
	}
}
