package hasher

import (
	"fmt"
	"strconv"
	"strings"
)

// Hasher types used in function New
const (
	// TypePlain is a plain hasher
	TypePlain = "plain"

	// TypeMD5 is a MD5 hasher
	TypeMD5 = "md5"

	// TypeSHA1 is a SHA-1 hasher
	TypeSHA1 = "sha1"

	// TypeSHA224 is a SHA-224 hasher
	TypeSHA224 = "sha224"

	// TypeSHA256 is a SHA-256 hasher
	TypeSHA256 = "sha256"

	// TypeSHA384 is a SHA-384 hasher
	TypeSHA384 = "sha384"

	// TypeSHA512 is a SHA-512 hasher
	TypeSHA512 = "sha512"

	// TypeSHA512_224 is a SHA-512/224 hasher
	TypeSHA512_224 = "sha512_224"

	// TypeSHA512_256 is a SHA-512/256 hasher
	TypeSHA512_256 = "sha512_256"
)

// Hasher interface
type Hasher interface {
	// Code returns internal hasher code
	Code() string

	Hash(string) []byte

	SetPassword(string)

	Check(string) bool

	String() string
}

// NewFromString returns a new Hasher object who is based on string representation of a hasher (e.x. from database)
func NewFromString(password string) (Hasher, error) {
	p := strings.Split(password, "$")
	switch p[0] {
	case PlainHasher{}.Code():
		password := []byte(p[1])
		return &PlainHasher{Password: &password}, nil
	case MD5Hasher{}.Code():
		iter, _ := strconv.Atoi(p[1])
		password := []byte(p[3])
		return &MD5Hasher{Salt: &p[2], Iter: &iter, Password: &password}, nil
	case SHA1Hasher{}.Code():
		iter, _ := strconv.Atoi(p[1])
		password := []byte(p[3])
		return &SHA1Hasher{Salt: &p[2], Iter: &iter, Password: &password}, nil
	case SHA224Hasher{}.Code():
		iter, _ := strconv.Atoi(p[1])
		password := []byte(p[3])
		return &SHA224Hasher{Salt: &p[2], Iter: &iter, Password: &password}, nil
	case SHA256Hasher{}.Code():
		iter, _ := strconv.Atoi(p[1])
		password := []byte(p[3])
		return &SHA256Hasher{Salt: &p[2], Iter: &iter, Password: &password}, nil
	case SHA384Hasher{}.Code():
		iter, _ := strconv.Atoi(p[1])
		password := []byte(p[3])
		return &SHA384Hasher{Salt: &p[2], Iter: &iter, Password: &password}, nil
	case SHA512Hasher{}.Code():
		iter, _ := strconv.Atoi(p[1])
		password := []byte(p[3])
		return &SHA512Hasher{Salt: &p[2], Iter: &iter, Password: &password}, nil
	case SHA512_224Hasher{}.Code():
		iter, _ := strconv.Atoi(p[1])
		password := []byte(p[3])
		return &SHA512_224Hasher{Salt: &p[2], Iter: &iter, Password: &password}, nil
	case SHA512_256Hasher{}.Code():
		iter, _ := strconv.Atoi(p[1])
		password := []byte(p[3])
		return &SHA512_256Hasher{Salt: &p[2], Iter: &iter, Password: &password}, nil
	}
	return nil, fmt.Errorf("Unsupported hasher %s", p[0])
}

// New returns new hasher of type hasherType
func New(hasherType string) (Hasher, error) {
	if hasherType == TypePlain {
		return &PlainHasher{}, nil
	} else if hasherType == TypeMD5 {
		return &MD5Hasher{}, nil
	} else if hasherType == TypeSHA1 {
		return &SHA1Hasher{}, nil
	} else if hasherType == TypeSHA224 {
		return &SHA224Hasher{}, nil
	} else if hasherType == TypeSHA256 {
		return &SHA256Hasher{}, nil
	} else if hasherType == TypeSHA384 {
		return &SHA384Hasher{}, nil
	} else if hasherType == TypeSHA512 {
		return &SHA512Hasher{}, nil
	} else if hasherType == TypeSHA512_224 {
		return &SHA512_224Hasher{}, nil
	} else if hasherType == TypeSHA512_256 {
		return &SHA512_256Hasher{}, nil
	}
	return nil, fmt.Errorf("Unsupported hasher %s", hasherType)
}
