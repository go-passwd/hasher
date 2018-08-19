package hasher

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSHA512_224Hasher_String(t *testing.T) {
	salt := "salt"
	iter := 1
	password := []byte("password")
	h := SHA512_224Hasher{Salt: &salt, Iter: &iter, Password: &password, Marshaler: &DjangoMarshaler}

	w := "sha512_224$1$salt$70617373776f7264"
	g := h.String()
	assert.Equal(t, w, g)

	h = SHA512_224Hasher{Salt: &salt, Iter: &iter, Password: &password}
	assert.Panics(t, assert.PanicTestFunc(func() {
		_ = h.String()
	}))
}

func TestSHA512_224Hasher_Check(t *testing.T) {
	salt := "salt"
	iter := 1
	password := []byte{0x8a, 0x63, 0xce, 0xaa, 0xc7, 0xf7, 0xb6, 0x9, 0x75, 0xd6, 0x1b, 0xc1, 0xb8, 0xb1, 0xc7, 0x6e, 0xc7, 0xde, 0x6c, 0x2, 0x26, 0xb7, 0xaf, 0x60, 0x63, 0x3e, 0xc5, 0xe}
	h := SHA512_224Hasher{Salt: &salt, Iter: &iter, Password: &password}

	check := h.Check("password")
	assert.Truef(t, check, "Passwords are equal")

	check = h.Check("password2")
	assert.Falsef(t, check, "Passwords are not equal")
}

func TestSHA512_224Hasher_Hash(t *testing.T) {
	salt := "salt"
	iter := 1
	password := []byte{0x8a, 0x63, 0xce, 0xaa, 0xc7, 0xf7, 0xb6, 0x9, 0x75, 0xd6, 0x1b, 0xc1, 0xb8, 0xb1, 0xc7, 0x6e, 0xc7, 0xde, 0x6c, 0x2, 0x26, 0xb7, 0xaf, 0x60, 0x63, 0x3e, 0xc5, 0xe}
	h := SHA512_224Hasher{Salt: &salt, Iter: &iter}

	g := h.Hash("password")
	assert.Equal(t, password, g)
}

func TestSHA512_224Hasher_Hash_Empty(t *testing.T) {
	h := SHA512_224Hasher{}
	h.Hash("password")
	assert.NotNil(t, h.Iter)
	assert.NotNil(t, h.Salt)
}

func TestSHA512_224Hasher_SetPassword(t *testing.T) {
	h := SHA512_224Hasher{}
	h.SetPassword("password")
	assert.NotNil(t, h.Password)
}
