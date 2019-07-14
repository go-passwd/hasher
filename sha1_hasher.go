package hasher

import (
	"bytes"
	"crypto/sha1"

	randomstring "gopkg.in/go-passwd/randomstring.v1"
)

// SHA1Hasher hash password in SHA-1
type SHA1Hasher struct {
	Salt     *string
	Iter     *int
	Password *[]byte
}

// Code returns internal SHA-224 hasher code
func (h SHA1Hasher) Code() string {
	return TypeSHA1
}

// Hash a password
func (h *SHA1Hasher) Hash(password string) []byte {
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
		s := sha1.New()
		s.Write(bPassword)
		bPassword = s.Sum(nil)
	}

	return bPassword
}

// SetPassword sets a password
func (h *SHA1Hasher) SetPassword(plain string) {
	hash := h.Hash(plain)
	h.Password = &hash
}

// Check if hashed password is equal stored password hash
func (h *SHA1Hasher) Check(plain string) bool {
	return bytes.Compare(h.Hash(plain), *h.Password) == 0
}

func (h *SHA1Hasher) String() string {
	if h.Password == nil {
		panic("password is not set")
	}
	return string(*h.Password)
}
