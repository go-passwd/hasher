package hasher

import (
	"fmt"
	"strconv"
	"strings"
)

// Hasher interface
type Hasher interface {
	// Code returns internal hasher code
	Code() string

	Hash(string) string

	SetPassword(string)

	Check(string) bool

	String() string
}

// NewHasherFromString returns a new Hasher object who is based on string representation of a hasher (e.x. from database)
func NewHasherFromString(password string) (Hasher, error) {
	p := strings.Split(password, "$")
	switch p[0] {
	case PlainHasher{}.Code():
		return &PlainHasher{Password: &p[1]}, nil
	case MD5Hasher{}.Code():
		iter, _ := strconv.Atoi(p[1])
		return &MD5Hasher{Salt: &p[2], Iter: &iter, Password: &p[3]}, nil
	case SHA1Hasher{}.Code():
		iter, _ := strconv.Atoi(p[1])
		return &SHA1Hasher{Salt: &p[2], Iter: &iter, Password: &p[3]}, nil
	case SHA224Hasher{}.Code():
		iter, _ := strconv.Atoi(p[1])
		return &SHA224Hasher{Salt: &p[2], Iter: &iter, Password: &p[3]}, nil
	case SHA256Hasher{}.Code():
		iter, _ := strconv.Atoi(p[1])
		return &SHA256Hasher{Salt: &p[2], Iter: &iter, Password: &p[3]}, nil
	case SHA384Hasher{}.Code():
		iter, _ := strconv.Atoi(p[1])
		return &SHA384Hasher{Salt: &p[2], Iter: &iter, Password: &p[3]}, nil
	case SHA512Hasher{}.Code():
		iter, _ := strconv.Atoi(p[1])
		return &SHA512Hasher{Salt: &p[2], Iter: &iter, Password: &p[3]}, nil
	case SHA512_224Hasher{}.Code():
		iter, _ := strconv.Atoi(p[1])
		return &SHA512_224Hasher{Salt: &p[2], Iter: &iter, Password: &p[3]}, nil
	case SHA512_256Hasher{}.Code():
		iter, _ := strconv.Atoi(p[1])
		return &SHA512_256Hasher{Salt: &p[2], Iter: &iter, Password: &p[3]}, nil
	}
	return nil, fmt.Errorf("Unsupported hasher %s", p[0])
}

// NewSHA512_256Hasher returns new default SHA-512/256 hasher
func NewSHA512_256Hasher() Hasher {
	return &SHA512_256Hasher{}
}

// NewSHA512_224Hasher returns new default SHA-512/224 hasher
func NewSHA512_224Hasher() Hasher {
	return &SHA512_224Hasher{}
}

// NewSHA512Hasher returns new default SHA-512 hasher
func NewSHA512Hasher() Hasher {
	return &SHA512Hasher{}
}

// NewSHA384Hasher returns new default SHA-384 hasher
func NewSHA384Hasher() Hasher {
	return &SHA384Hasher{}
}

// NewSHA256Hasher returns new default SHA-256 hasher
func NewSHA256Hasher() Hasher {
	return &SHA256Hasher{}
}

// NewSHA224Hasher returns new default SHA-224 hasher
func NewSHA224Hasher() Hasher {
	return &SHA224Hasher{}
}

// NewSHA1Hasher returns new default SHA-224 hasher
func NewSHA1Hasher() Hasher {
	return &SHA1Hasher{}
}

// NewMD5Hasher returns new default MD5 hasher
func NewMD5Hasher() Hasher {
	return &MD5Hasher{}
}

// NewPlainHasher returns new default plain hasher
func NewPlainHasher() Hasher {
	return &PlainHasher{}
}
