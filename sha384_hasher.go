package hasher

import (
	"bytes"
	"crypto/sha512"

	randomstring "gopkg.in/go-passwd/randomstring.v1"
)

// SHA384Hasher hash password in SHA-384
type SHA384Hasher struct {
	Salt     *string
	Iter     *int
	Password *[]byte

	Marshaler Marshaler
}

// Code returns internal SHA-384 hasher code
func (h SHA384Hasher) Code() string {
	return TypeSHA384
}

// Hash a password
func (h *SHA384Hasher) Hash(password string) []byte {
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
		s := sha512.New384()
		s.Write(bPassword)
		bPassword = s.Sum(nil)
	}

	return bPassword
}

// SetPassword sets a password
func (h *SHA384Hasher) SetPassword(plain string) {
	hash := h.Hash(plain)
	h.Password = &hash
}

// Check if hashed password is equal stored password hash
func (h *SHA384Hasher) Check(plain string) bool {
	return bytes.Compare(h.Hash(plain), *h.Password) == 0
}

func (h *SHA384Hasher) String() string {
	if h.Marshaler == nil {
		panic("marshaler is not set")
	}
	s, _ := h.Marshaler.Marshal(h)
	return s
}
