package hasher

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"fmt"

	randomstring "gopkg.in/go-passwd/randomstring.v1"
)

// MD5Hasher hash password in MD5
type MD5Hasher struct {
	Salt     *string
	Iter     *int
	Password *[]byte
}

// Code returns internal MD5 hasher code
func (h MD5Hasher) Code() string {
	return TypeMD5
}

// Hash a password
func (h *MD5Hasher) Hash(password string) []byte {
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
		s := md5.New()
		s.Write(bPassword)
		bPassword = s.Sum(nil)
	}

	return bPassword
}

// SetPassword sets a password
func (h *MD5Hasher) SetPassword(plain string) {
	hash := h.Hash(plain)
	h.Password = &hash
}

// Check if hashed password is equal stored password hash
func (h *MD5Hasher) Check(plain string) bool {
	return bytes.Compare(h.Hash(plain), *h.Password) == 0
}

func (h *MD5Hasher) String() string {
	return fmt.Sprintf("%s$%d$%s$%s", h.Code(), *h.Iter, *h.Salt, hex.EncodeToString(*h.Password))
}
