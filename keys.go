package main

import (
	"crypto/rand"
	"crypto/sha1"
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

func generateAESKey(psw string, salt []byte) []byte {
	return pbkdf2.Key([]byte(psw), salt, 4096, 32, sha1.New)
}
