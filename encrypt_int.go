package simple_encrypt

import (
	"database/sql/driver"
	"errors"
	"strconv"
)

// EncryptInt is for encrypt an int (such as gender, enum). If anything error in the process of scanner or valuer,
// they will return the raw data, instead of nil
type EncryptInt struct {
	keyName string
	raw     *int
}

// Scan scans the value src from the database to the type EncryptInt
func (i *EncryptInt) Scan(src interface{}) error {
	// src might be null
	if src == nil {
		i.raw = nil
		return nil
	}
	// The src type must be string or []byte
	var source string
	switch src.(type) {
	case string:
		source = src.(string)
	case []byte:
		source = string(src.([]byte))
	default:
		i.raw = nil
		return errors.New("incompatible type for scan")
	}
	// Have to recover from panic because we always want to get the original data no matter what happen
	defer recoverFromPanicEncryptInt(i, source)
	// Decrypt the source by key with given key name
	plainTextString, err := decrypt(source, keys[i.keyName])
	if err != nil {
		tmp, err2 := strconv.Atoi(source)
		if err2 != nil {
			i.raw = nil
			return err2
		}
		i.raw = &tmp
		return err
	}
	tmp, err := strconv.Atoi(plainTextString)
	if err != nil {
		i.raw = nil
		return err
	}
	i.raw = &tmp
	return nil
}

// Value encrypts the value and save in the database
func (i EncryptInt) Value() (driver.Value, error) {
	if i.raw == nil {
		return nil, nil
	}
	plainTextString := strconv.Itoa(*i.raw)
	cipherTextString, err := encrypt(plainTextString, keys[i.keyName])
	if err != nil {
		return plainTextString, err
	}
	return cipherTextString, nil
}

// Int gets the raw int
func (i *EncryptInt) Int() int {
	if i.raw == nil {
		return 0
	}
	return *i.raw
}

// SetKeyName sets the key
func (i *EncryptInt) SetKeyName(keyName string) {
	i.keyName = keyName
}

// SetRaw sets the raw
func (i *EncryptInt) SetRaw(raw *int)  {
	i.raw = raw
}

// NewDefaultEncryptInt news an EncryptInt with default key name
// you must only use NewDefaultEncryptInt or NewEncryptInt to new an EncryptInt
func NewEncryptInt(raw *int) EncryptInt {
	return EncryptInt{
		keyName: DefaultKeyName,
		raw:     raw,
	}
}

// NewEncryptInt news an EncryptInt with given key name
// you must only use NewDefaultEncryptInt or NewEncryptInt to new an EncryptInt
func NewEncryptIntWithKeyName(keyName string, raw *int) EncryptInt {
	return EncryptInt{
		keyName: keyName,
		raw:     raw,
	}
}

// recoverFromPanicEncryptInt recovers from panic and get the plain int for EncryptInt
func recoverFromPanicEncryptInt(i *EncryptInt, source string) {
	if r := recover(); r != nil {
		tmp, err := strconv.Atoi(source)
		if err != nil {
			i.raw = nil
		}
		i.raw = &tmp
	}
}
