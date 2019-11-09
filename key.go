package simple_encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
)

// To save the keys. You can simply use default key,
// or you can init multiple keys, and encrypt different record with different keys
var keys map[string]*cipher.Block

const DefaultKeyName = "default"

func init()  {
	keys = make(map[string]*cipher.Block, 0)
}

// InitDefaultKey inits the default key
func InitDefaultKey(key string) error {
	if keys[DefaultKeyName] != nil {
		return errors.New("do not init the key twice")
	}
	block, err := initBlock(key)
	if err != nil {
		return err
	}
	keys[DefaultKeyName] = block
	return nil
}

// InitKeys inits multiple keys with unique names to encrypts records with different keys
func InitKeys(keysMap map[string]string) error {
	// Check if there are duplicate keys and illegal keys
	blocks := make(map[string]*cipher.Block, 0)
	for name, key := range keysMap {
		if keys[name] != nil {
			return errors.New("do not init the key twice")
		}
		block, err := initBlock(key)
		if err != nil {
			return err
		}
		blocks[name] = block
	}
	for name, block := range blocks {
		keys[name] = block
	}
	return nil
}

// initBlock inits a block from given key
func initBlock(key string) (*cipher.Block, error) {
	// key must be a hex string with length of 32, 48 or 64, corresponding to aes 128, 192, 256 cbc
	keyBytes, err := hex.DecodeString(key)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, err
	}
	return &block, nil
}
