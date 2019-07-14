package hasher

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSHA224Hasher_String(t *testing.T) {
	salt := "salt"
	iter := 1
	h := SHA224Hasher{Salt: &salt, Iter: &iter}
	h.SetPassword("password")

	w := string([]byte{0x5f, 0xe3, 0x1e, 0x9a, 0xab, 0x92, 0x21, 0x9c, 0x4, 0x72, 0x73, 0x21, 0x9a, 0xb1, 0x2e, 0xba, 0x40, 0xc, 0x93, 0x12, 0xae, 0x74, 0x25, 0x87, 0x6, 0xf1, 0x44, 0xe1})
	g := h.String()
	assert.Equal(t, w, g)

	h = SHA224Hasher{Salt: &salt, Iter: &iter}
	assert.Panics(t, assert.PanicTestFunc(func() {
		_ = h.String()
	}))
}

func TestSHA224Hasher_Check(t *testing.T) {
	salt := "salt"
	iter := 1
	h := SHA224Hasher{Salt: &salt, Iter: &iter}
	h.SetPassword("password")

	check := h.Check("password")
	assert.Truef(t, check, "Passwords are equal")

	check = h.Check("password2")
	assert.Falsef(t, check, "Passwords are not equal")
}

func TestSHA224Hasher_Hash(t *testing.T) {
	salt := "salt"
	iter := 1
	password := []byte{0x5f, 0xe3, 0x1e, 0x9a, 0xab, 0x92, 0x21, 0x9c, 0x4, 0x72, 0x73, 0x21, 0x9a, 0xb1, 0x2e, 0xba, 0x40, 0xc, 0x93, 0x12, 0xae, 0x74, 0x25, 0x87, 0x6, 0xf1, 0x44, 0xe1}
	h := SHA224Hasher{Salt: &salt, Iter: &iter}

	g := h.Hash("password")
	assert.Equal(t, password, g)
}

func TestSHA224Hasher_Hash_Empty(t *testing.T) {
	h := SHA224Hasher{}
	h.Hash("password")
	assert.NotNil(t, h.Iter)
	assert.NotNil(t, h.Salt)
}

func TestSHA224Hasher_SetPassword(t *testing.T) {
	h := SHA224Hasher{}
	h.SetPassword("password")
	assert.NotNil(t, h.Password)
}
