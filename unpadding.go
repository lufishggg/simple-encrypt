package simple_encrypt

// pkcs7UnPadding unpads the text
func pkcs7Unpadding(text []byte) []byte {
	length := len(text)
	unPadding := int(text[length-1])
	return text[:(length - unPadding)]
}
