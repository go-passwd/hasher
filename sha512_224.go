package hasher

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"fmt"

	randomstring "gopkg.in/randomstring.v1"
)

// SHA512_224Hasher hash password in SHA-512/224
type SHA512_224Hasher struct {
	Salt     *string
	Iter     *int
	Password *[]byte
}

// Code returns internal SHA-512/224 hasher code
func (h SHA512_224Hasher) Code() string {
	return TypeSHA512_224
}

// Hash a password
func (h *SHA512_224Hasher) Hash(password string) []byte {
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
		s := sha512.New512_224()
		s.Write(bPassword)
		bPassword = s.Sum(nil)
	}

	return bPassword
}

// SetPassword sets a password
func (h *SHA512_224Hasher) SetPassword(plain string) {
	hash := h.Hash(plain)
	h.Password = &hash
}

// Check if hashed password is equal stored password hash
func (h *SHA512_224Hasher) Check(plain string) bool {
	return bytes.Compare(h.Hash(plain), *h.Password) == 0
}

func (h *SHA512_224Hasher) String() string {
	return fmt.Sprintf("%s$%d$%s$%s", h.Code(), *h.Iter, *h.Salt, hex.EncodeToString(*h.Password))
}
