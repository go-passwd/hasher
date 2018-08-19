package hasher

import (
	"bytes"
)

// PlainHasher stored password as plain text
type PlainHasher struct {
	Password *[]byte

	Marshaler Marshaler
}

// Code returns internal plain hasher code
func (h PlainHasher) Code() string {
	return TypePlain
}

// Hash a password
func (h *PlainHasher) Hash(password string) []byte {
	return []byte(password)
}

// SetPassword sets a password
func (h *PlainHasher) SetPassword(password string) {
	_password := h.Hash(password)
	h.Password = &_password
}

// Check if password is equal stored password
func (h *PlainHasher) Check(plain string) bool {
	return bytes.Compare(h.Hash(plain), *h.Password) == 0
}

func (h *PlainHasher) String() string {
	if h.Marshaler == nil {
		panic("marshaler is not set")
	}
	s, _ := h.Marshaler.Marshal(h)
	return s
}
