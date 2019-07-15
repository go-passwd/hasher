package hasher

import (
	"fmt"
)

const (
	// DefaultSaltLength is a default salt length when is not set manually
	DefaultSaltLength = 20

	// DefaultIter is a default iterations counter when is not set manually
	DefaultIter = 2048
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
	// Code returns internal hasher code (go-passwd/marshaler)
	Code() string

	// Hash password
	Hash(string) []byte

	// SetPassword
	SetPassword(string)

	Check(string) bool

	// String representation of hashed password
	String() string
}

// NewHasherFunc describes function that returns new hasher
type NewHasherFunc func(iterations *int, salt *string, hashedPassword *[]byte) Hasher

var (
	// Internal map of registered hashers
	registeredHashers = map[string]NewHasherFunc{
		TypePlain:      NewHasherFunc(NewPlainHasher),
		TypeMD5:        NewHasherFunc(NewMD5Hasher),
		TypeSHA1:       NewHasherFunc(NewSHA1Hasher),
		TypeSHA224:     NewHasherFunc(NewSHA224Hasher),
		TypeSHA256:     NewHasherFunc(NewSHA256Hasher),
		TypeSHA384:     NewHasherFunc(NewSHA384Hasher),
		TypeSHA512:     NewHasherFunc(NewSHA512Hasher),
		TypeSHA512_224: NewHasherFunc(NewSHA512_224Hasher),
		TypeSHA512_256: NewHasherFunc(NewSHA512_256Hasher),
	}
)

// Register a new hasher
func Register(code string, hshr NewHasherFunc) error {
	if registeredHashers[code] != nil {
		return fmt.Errorf("hasher %s already registered", code)
	}
	registeredHashers[code] = hshr
	return nil
}

// New returns new hasher of type hasherType
func New(hasherType string) (Hasher, error) {
	if registeredHashers[hasherType] != nil {
		return registeredHashers[hasherType](nil, nil, nil), nil
	}
	return nil, fmt.Errorf("Unsupported hasher %s", hasherType)
}

// NewWithParams returns new hasher of type hasherType and set hasher params
func NewWithParams(hasherType string, iterations *int, salt *string, hashedPassword *[]byte) (Hasher, error) {
	if registeredHashers[hasherType] != nil {
		return registeredHashers[hasherType](iterations, salt, hashedPassword), nil
	}
	return nil, fmt.Errorf("Unsupported hasher %s", hasherType)
}
