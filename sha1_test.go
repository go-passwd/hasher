package hasher

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSHA1Hasher_String(t *testing.T) {
	salt := "salt"
	iter := 1
	password := []byte("password")
	h := SHA1Hasher{Salt: &salt, Iter: &iter, Password: &password}

	w := "sha1$1$salt$70617373776f7264"
	g := h.String()
	assert.Equal(t, w, g)
}

func TestSHA1Hasher_Check(t *testing.T) {
	salt := "salt"
	iter := 1
	password := []byte{0x59, 0xb3, 0xe8, 0xd6, 0x37, 0xcf, 0x97, 0xed, 0xbe, 0x23, 0x84, 0xcf, 0x59, 0xcb, 0x74, 0x53, 0xdf, 0xe3, 0x7, 0x89}
	h := SHA1Hasher{Salt: &salt, Iter: &iter, Password: &password}

	check := h.Check("password")
	assert.Truef(t, check, "Passwords are equal")

	check = h.Check("password2")
	assert.Falsef(t, check, "Passwords are not equal")
}

func TestSHA1Hasher_Hash(t *testing.T) {
	salt := "salt"
	iter := 1
	password := []byte{0x59, 0xb3, 0xe8, 0xd6, 0x37, 0xcf, 0x97, 0xed, 0xbe, 0x23, 0x84, 0xcf, 0x59, 0xcb, 0x74, 0x53, 0xdf, 0xe3, 0x7, 0x89}
	h := SHA1Hasher{Salt: &salt, Iter: &iter}

	g := h.Hash("password")
	assert.Equal(t, password, g)
}

func TestSHA1Hasher_Hash_Empty(t *testing.T) {
	h := SHA1Hasher{}
	h.Hash("password")
	assert.NotNil(t, h.Iter)
	assert.NotNil(t, h.Salt)
}

func TestSHA1Hasher_SetPassword(t *testing.T) {
	h := SHA1Hasher{}
	h.SetPassword("password")
	assert.NotNil(t, h.Password)
}
