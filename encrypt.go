package simple_encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

// encrypt encrypts the data through aes
func encrypt(plainTextString string, block *cipher.Block) (string, error) {
	// If block is null
	if block == nil {
		return "", errors.New("haven't init block")
	}
	// Get the plain text bytes from plain text string and padding it
	plainTextBytes := []byte(plainTextString)
	plainTextBytes = pkcs7Padding(plainTextBytes)
	if len(plainTextBytes)%aes.BlockSize != 0 {
		return "", errors.New("plaintext is not a multiple of the block size")
	}
	// Make the cipher text bytes
	cipherTextBytes := make([]byte, aes.BlockSize+len(plainTextBytes))
	// Random generate iv
	iv := cipherTextBytes[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	// Encrypt
	mode := cipher.NewCBCEncrypter(*block, iv)
	mode.CryptBlocks(cipherTextBytes[aes.BlockSize:], plainTextBytes)
	// Base64 encodes the cipher text
	cipherTextString := base64.StdEncoding.EncodeToString(cipherTextBytes)
	return cipherTextString, nil
}
