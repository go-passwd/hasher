package hasher

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSHA512_256Hasher_String(t *testing.T) {
	salt := "salt"
	iter := 1
	password := []byte("password")
	h := SHA512_256Hasher{Salt: &salt, Iter: &iter, Password: &password}

	w := "sha512_256$1$salt$70617373776f7264"
	g := h.String()
	assert.Equal(t, w, g)
}

func TestSHA512_256Hasher_Check(t *testing.T) {
	salt := "salt"
	iter := 1
	password := []byte{0x5, 0x42, 0x18, 0x82, 0x8, 0x71, 0x4e, 0x74, 0xc7, 0x71, 0x7, 0x55, 0x81, 0x68, 0xd7, 0xfe, 0xa6, 0x1d, 0x85, 0xbb, 0xab, 0x7a, 0x5c, 0x88, 0xaf, 0x3c, 0xf6, 0xfa, 0x20, 0x68, 0xb6, 0x1}
	h := SHA512_256Hasher{Salt: &salt, Iter: &iter, Password: &password}

	check := h.Check("password")
	assert.Truef(t, check, "Passwords are equal")

	check = h.Check("password2")
	assert.Falsef(t, check, "Passwords are not equal")
}

func TestSHA512_256Hasher_Hash(t *testing.T) {
	salt := "salt"
	iter := 1
	password := []byte{0x5, 0x42, 0x18, 0x82, 0x8, 0x71, 0x4e, 0x74, 0xc7, 0x71, 0x7, 0x55, 0x81, 0x68, 0xd7, 0xfe, 0xa6, 0x1d, 0x85, 0xbb, 0xab, 0x7a, 0x5c, 0x88, 0xaf, 0x3c, 0xf6, 0xfa, 0x20, 0x68, 0xb6, 0x1}
	h := SHA512_256Hasher{Salt: &salt, Iter: &iter}

	g := h.Hash("password")
	assert.Equal(t, password, g)
}

func TestSHA512_256Hasher_Hash_Empty(t *testing.T) {
	h := SHA512_256Hasher{}
	h.Hash("password")
	assert.NotNil(t, h.Iter)
	assert.NotNil(t, h.Salt)
}

func TestSHA512_256Hasher_SetPassword(t *testing.T) {
	h := SHA512_256Hasher{}
	h.SetPassword("password")
	assert.NotNil(t, h.Password)
}
