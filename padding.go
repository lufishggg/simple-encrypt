package simple_encrypt

import (
	"bytes"
	"crypto/aes"
)

// pkcs7Padding pads the text
func pkcs7Padding(text []byte) []byte {
	padding := aes.BlockSize - len(text)%aes.BlockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(text, padText...)
}
