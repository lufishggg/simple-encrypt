package simple_encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
)

// decrypt decrypts the data through aes
func decrypt(cipherTextString string, block *cipher.Block) (string, error) {
	if block == nil {
		return "", errors.New("block is not initialized")
	}
	cipherTextBytes, err := base64.StdEncoding.DecodeString(cipherTextString)
	if err != nil {
		return "", err
	}
	if len(cipherTextBytes) < aes.BlockSize {
		return "", errors.New("cipher text is too short")
	}
	// Get the iv from cipher text
	iv := cipherTextBytes[:aes.BlockSize]
	cipherTextBytes = cipherTextBytes[aes.BlockSize:]
	if len(cipherTextBytes) % aes.BlockSize != 0 {
		return "", errors.New("cipher text is not a multiple of the block size")
	}
	// Decrypt
	mode := cipher.NewCBCDecrypter(*block, iv)
	mode.CryptBlocks(cipherTextBytes, cipherTextBytes)
	// Unpadding
	cipherTextBytes = pkcs7Unpadding(cipherTextBytes)
	ciphertextStr := string(cipherTextBytes)
	return ciphertextStr, nil
}
