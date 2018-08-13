package hasher

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	randomstring "gopkg.in/randomstring.v1"
)

// SHA224Hasher hash password in SHA-224
type SHA224Hasher struct {
	Salt     *string
	Iter     *int
	Password *[]byte
}

// Code returns internal SHA-224 hasher code
func (h SHA224Hasher) Code() string {
	return TypeSHA224
}

// Hash a password
func (h *SHA224Hasher) Hash(password string) []byte {
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
		s := sha256.New224()
		s.Write(bPassword)
		bPassword = s.Sum(nil)
	}

	return bPassword
}

// SetPassword sets a password
func (h *SHA224Hasher) SetPassword(plain string) {
	hash := h.Hash(plain)
	h.Password = &hash
}

// Check if hashed password is equal stored password hash
func (h *SHA224Hasher) Check(plain string) bool {
	return bytes.Compare(h.Hash(plain), *h.Password) == 0
}

func (h *SHA224Hasher) String() string {
	return fmt.Sprintf("%s$%d$%s$%s", h.Code(), *h.Iter, *h.Salt, hex.EncodeToString(*h.Password))
}
