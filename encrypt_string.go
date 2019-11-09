package simple_encrypt

import (
	"database/sql/driver"
	"errors"
)

// EncryptString is for encrypt a string. If anything error in the process of scanner or valuer,
// they will return the raw data, instead of nil
type EncryptString struct {
	keyName string
	raw     *string
}

// Scan scans the value src from the database to the type EncryptString
func (s *EncryptString) Scan(src interface{}) error {
	// src might be null
	if src == nil {
		s.raw = nil
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
		s.raw = nil
		return errors.New("incompatible type for scan")
	}
	// Have to recover from panic because we always want to get the original data no matter what happen
	defer recoverFromPanicEncryptString(s, source)
	// Decrypt the source by key with given key name
	plainTextString, err := decrypt(source, keys[s.keyName])
	if err != nil {
		s.raw = &source
		return nil
	}
	s.raw = &plainTextString
	return nil
}

// Value encrypts the value and save in the database
func (s EncryptString) Value() (driver.Value, error) {
	if s.raw == nil{
		return nil, nil
	}
	cipherTextString, err := encrypt(*s.raw, keys[s.keyName])
	if err != nil {
		return *s.raw, err
	}
	return cipherTextString, nil
}

// Int gets the raw string
func (s *EncryptString) String() string {
	if s.raw == nil {
		return ""
	}
	return *s.raw
}

// NewEncryptString news a default EncryptString
func NewEncryptString(raw *string) EncryptString {
	return EncryptString{
		keyName: DefaultKeyName,
		raw:     raw,
	}
}

// NewEncryptStringWithKeyName news an EncryptString with given key name
// you must only use NewDefaultEncryptString or NewEncryptString to new an EncryptString
func NewEncryptStringWithKeyName(keyName string, raw *string) EncryptString {
	return EncryptString{
		keyName: keyName,
		raw: raw,
	}
}

// recoverFromPanicEncryptString recovers from panic and get the plain string for EncryptString
func recoverFromPanicEncryptString(i *EncryptString, source string) {
	if r := recover(); r != nil {
		i.raw = &source
	}
}