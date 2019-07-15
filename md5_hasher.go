package hasher

import (
	"bytes"
	"crypto/md5"

	randomstring "gopkg.in/go-passwd/randomstring.v1"
)

// MD5Hasher hash password in MD5
type MD5Hasher struct {
	Salt     *string
	Iter     *int
	Password *[]byte
}

// NewMD5Hasher returns a new MD5 hasher instance
func NewMD5Hasher(iterations *int, salt *string, hashedPassword *[]byte) Hasher {
	return &MD5Hasher{
		Iter:     iterations,
		Salt:     salt,
		Password: hashedPassword,
	}
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
	if h.Password == nil {
		panic("password is not set")
	}
	return string(*h.Password)
}
