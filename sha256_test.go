package hasher

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSHA256Hasher_String(t *testing.T) {
	salt := "salt"
	iter := 1
	password := []byte("password")
	h := SHA256Hasher{Salt: &salt, Iter: &iter, Password: &password}

	w := "sha256$1$salt$70617373776f7264"
	g := h.String()
	assert.Equal(t, w, g)
}

func TestSHA256Hasher_Check(t *testing.T) {
	salt := "salt"
	iter := 1
	password := []byte{0x13, 0x60, 0x1b, 0xda, 0x4e, 0xa7, 0x8e, 0x55, 0xa0, 0x7b, 0x98, 0x86, 0x6d, 0x2b, 0xe6, 0xbe, 0x7, 0x44, 0xe3, 0x86, 0x6f, 0x13, 0xc0, 0xc, 0x81, 0x1c, 0xab, 0x60, 0x8a, 0x28, 0xf3, 0x22}
	h := SHA256Hasher{Salt: &salt, Iter: &iter, Password: &password}

	check := h.Check("password")
	assert.Truef(t, check, "Passwords are equal")

	check = h.Check("password2")
	assert.Falsef(t, check, "Passwords are not equal")
}

func TestSHA256Hasher_Hash(t *testing.T) {
	salt := "salt"
	iter := 1
	password := []byte{0x13, 0x60, 0x1b, 0xda, 0x4e, 0xa7, 0x8e, 0x55, 0xa0, 0x7b, 0x98, 0x86, 0x6d, 0x2b, 0xe6, 0xbe, 0x7, 0x44, 0xe3, 0x86, 0x6f, 0x13, 0xc0, 0xc, 0x81, 0x1c, 0xab, 0x60, 0x8a, 0x28, 0xf3, 0x22}
	h := SHA256Hasher{Salt: &salt, Iter: &iter}

	g := h.Hash("password")
	assert.Equal(t, password, g)
}

func TestSHA256Hasher_Hash_Empty(t *testing.T) {
	h := SHA256Hasher{}
	h.Hash("password")
	assert.NotNil(t, h.Iter)
	assert.NotNil(t, h.Salt)
}

func TestSHA256Hasher_SetPassword(t *testing.T) {
	h := SHA256Hasher{}
	h.SetPassword("password")
	assert.NotNil(t, h.Password)
}
