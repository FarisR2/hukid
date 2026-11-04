// Package secretbox implements authenticated encryption for recoverable secrets.
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"

	"hukid.local/platform/internal/authentication"
)

type Box struct {
	aead    cipher.AEAD
	version string
	random  io.Reader
}

func New(key []byte, version string, random io.Reader) (*Box, error) {
	if len(key) != 32 || len(version) == 0 || len(version) > 128 || random == nil {
		return nil, errors.New("invalid encryption configuration")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead, version, random}, nil
}

func (b *Box) Seal(plaintext []byte, purpose string) (authentication.Envelope, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := io.ReadFull(b.random, nonce); err != nil {
		return authentication.Envelope{}, err
	}
	return authentication.Envelope{Ciphertext: b.aead.Seal(nil, nonce, plaintext, []byte(purpose+":"+b.version)), Nonce: nonce, KeyVersion: b.version}, nil
}

func (b *Box) Open(e authentication.Envelope, purpose string) ([]byte, error) {
	if e.KeyVersion != b.version || len(e.Nonce) != b.aead.NonceSize() {
		return nil, errors.New("invalid encrypted envelope")
	}
	return b.aead.Open(nil, e.Nonce, e.Ciphertext, []byte(purpose+":"+b.version))
}
