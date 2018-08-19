package hasher

import (
	"bytes"
	"crypto/sha256"

	randomstring "gopkg.in/go-passwd/randomstring.v1"
)

// SHA256Hasher hash password in SHA256
type SHA256Hasher struct {
	Salt     *string
	Iter     *int
	Password *[]byte

	Marshaler Marshaler
}

// Code returns internal SHA-224 hasher code
func (h SHA256Hasher) Code() string {
	return TypeSHA256
}

// Hash a password
func (h *SHA256Hasher) Hash(password string) []byte {
	if h.Salt == nil {
		salt := randomstring.Generate(DefaultSaltLength)
		h.Salt = &salt
	}

	if h.Iter == nil {
		iter := DefaultIter
		h.Iter = &iter
	}

	bPassword := []byte(*h.Salt + password)
	for i := 0; i < *h.Iter; i++ {
		s := sha256.New()
		s.Write(bPassword)
		bPassword = s.Sum(nil)
	}

	return bPassword
}

// SetPassword sets a password
func (h *SHA256Hasher) SetPassword(plain string) {
	hash := h.Hash(plain)
	h.Password = &hash
}

// Check if hashed password is equal stored password hash
func (h *SHA256Hasher) Check(plain string) bool {
	return bytes.Compare(h.Hash(plain), *h.Password) == 0
}

func (h *SHA256Hasher) String() string {
	if h.Marshaler == nil {
		panic("marshaler is not set")
	}
	s, _ := h.Marshaler.Marshal(h)
	return s
}
