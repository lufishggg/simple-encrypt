package simple_encrypt

import (
	"crypto/aes"
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"testing"
)

// TestInitDefaultKey tests the correctness of the default key initialization
func TestInitDefaultKey(t *testing.T) {
	assert.Error(t, InitDefaultKey("0123456789"), "key length should be 32, 48 or 64")
	assert.Error(t, InitDefaultKey("abcdef0123456789abcdefghijklmnop"), "key should be hex string")
	_ = InitDefaultKey("0123456789abcdef0123456789abcdef")
	block, _ := initBlock("0123456789abcdef0123456789abcdef")
	assert.Equal(t, block, keys[DefaultKeyName], "should be the right default key")
	assert.Error(t, InitDefaultKey("0123456789abcdef0123456789abcdef"), "should not init twice")
}

// TestInitKeys tests the correctness of the keys initialization
func TestInitKeys(t *testing.T) {
	_ = InitKeys(map[string]string{"test1": "0123456789abcdef0123456789abcdef"})
	block, _ := initBlock("0123456789abcdef0123456789abcdef")
	assert.Equal(t, block, keys["test1"], "should be the right test1 key")
	assert.Error(t, InitKeys(map[string]string{"test1": "0123456789abcdef0123456789abcdef"}), "should not init twice")
}

// TestEncryptAndDecrypt tests the correctness of the encrypt and decrypt function
func TestEncryptAndDecrypt(t *testing.T) {
	keyBytes, _ := hex.DecodeString("0123456789abcdef0123456789abcdef")
	block, _ := aes.NewCipher(keyBytes)
	plainTextString := "I am plain text"
	cipherTextString, _ := encrypt(plainTextString, &block)
	plainTextStringNew, _ := decrypt(cipherTextString, &block)
	assert.Equal(t, "I am plain text", plainTextStringNew, "should be the same")
}

// TestEncryptStringScan1 tests the correctness of the scan function
func TestEncryptStringScan1(t *testing.T) {
	es := NewEncryptStringWithKeyName("test", nil)
	_ = InitKeys(map[string]string{"test": "0123456789abcdef0123456789abcdef"})
	_ = es.Scan("BFpTEtSThsjeCnt7wDbTLGFBmbdgGHATtsDb5Fty9Rs=")
	assert.Equal(t, "I am plain text", es.String(), "should get the right plain text")
}

// TestEncryptStringScan2 tests the correctness of the scan function
func TestEncryptStringScan2(t *testing.T) {
	es := NewEncryptStringWithKeyName("test", nil)
	_ = InitKeys(map[string]string{"test": "0123456789abcdef0123456789abcdef"})
	_ = es.Scan(nil)
	assert.Equal(t, true, es.raw == nil, "should get nil if src is nil")
	_ = es.Scan("abc")
	assert.Equal(t, "abc", es.String(), "should return original data if it is not a cipher text")
}

// TestEncryptStringValue tests the correctness of the value function
func TestEncryptStringValue(t *testing.T) {
	raw := "I am plain text"
	es := NewEncryptStringWithKeyName("test", &raw)
	_ = InitKeys(map[string]string{"test": "0123456789abcdef0123456789abcdef"})
	value, _ := es.Value()
	cipherTextString := value.(string)
	_ = es.Scan(cipherTextString)
	assert.Equal(t, "I am plain text", es.String(), "should get the right plain text")
}

// TestEncryptStringInt tests the correctness of the scan function
func TestEncryptIntScan(t *testing.T) {
	ei := NewEncryptIntWithKeyName("test", nil)
	_ = InitKeys(map[string]string{"test": "0123456789abcdef0123456789abcdef"})
	_ = ei.Scan("mBYP/b2SJ/uQjUjW16FWT4xNvLS2a1Q+gBc8Y8pc8TM=")
	assert.Equal(t, 12345, ei.Int(), "should get the right plain int")
}

// TestEncryptStringValue tests the correctness of the value function
func TestEncryptIntValue(t *testing.T) {
	raw := 12345
	ei := NewEncryptIntWithKeyName("test", &raw)
	_ = InitKeys(map[string]string{"test": "0123456789abcdef0123456789abcdef"})
	value, _ := ei.Value()
	cipherTextString := value.(string)
	_ = ei.Scan(cipherTextString)
	assert.Equal(t, 12345, ei.Int(), "should get the right plain int")
}
