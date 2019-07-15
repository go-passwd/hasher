package hasher

import (
	"bytes"
	"crypto/sha512"

	randomstring "gopkg.in/go-passwd/randomstring.v1"
)

// SHA512Hasher hash password in SHA-512
type SHA512Hasher struct {
	Salt     *string
	Iter     *int
	Password *[]byte
}

// NewSHA512Hasher returns a new plain hasher instance
func NewSHA512Hasher(iterations *int, salt *string, hashedPassword *[]byte) Hasher {
	return &SHA512Hasher{
		Iter:     iterations,
		Salt:     salt,
		Password: hashedPassword,
	}
}

// Code returns internal SHA-512 hasher code
func (h SHA512Hasher) Code() string {
	return TypeSHA512
}

// Hash a password
func (h *SHA512Hasher) Hash(password string) []byte {
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
		s := sha512.New()
		s.Write(bPassword)
		bPassword = s.Sum(nil)
	}

	return bPassword
}

// SetPassword sets a password
func (h *SHA512Hasher) SetPassword(plain string) {
	hash := h.Hash(plain)
	h.Password = &hash
}

// Check if hashed password is equal stored password hash
func (h *SHA512Hasher) Check(plain string) bool {
	return bytes.Compare(h.Hash(plain), *h.Password) == 0
}

func (h *SHA512Hasher) String() string {
	if h.Password == nil {
		panic("password is not set")
	}
	return string(*h.Password)
}
