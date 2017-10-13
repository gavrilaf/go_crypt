package main

import (
	"crypto/rand"
	"crypto/sha1"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"io"
)

const (
	SALT_LENGTH = 8
)

func generateSalt() ([]byte, error) {
	salt := make([]byte, SALT_LENGTH)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	return salt, nil
}

func generatePBKDF2Key(psw string, salt []byte) []byte {
	return pbkdf2.Key([]byte(psw), salt, 4096, 32, sha1.New)
}

func generateKey(psw string, f KeyDerivationFunc) (*CryptoKey, error) {
	salt, err := generateSalt()
	if err != nil {
		return nil, fmt.Errorf("Generate salt error: %v", err.Error())
	}

	key := generatePBKDF2Key(psw, salt)

	return &CryptoKey{salt, key}, nil
}
