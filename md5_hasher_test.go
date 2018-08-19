package hasher

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMD5Hasher_String(t *testing.T) {
	salt := "salt"
	iter := 1
	password := []byte("password")
	h := MD5Hasher{Salt: &salt, Iter: &iter, Password: &password, Marshaler: &DjangoMarshaler}

	w := "md5$1$salt$70617373776f7264"
	g := h.String()
	assert.Equal(t, w, g)

	h = MD5Hasher{Salt: &salt, Iter: &iter, Password: &password}
	assert.Panics(t, assert.PanicTestFunc(func() {
		_ = h.String()
	}))
}

func TestMD5Hasher_Check(t *testing.T) {
	salt := "salt"
	iter := 1
	password := []byte{0x67, 0xa1, 0xe0, 0x9b, 0xb1, 0xf8, 0x3f, 0x50, 0x07, 0xdc, 0x11, 0x9c, 0x14, 0xd6, 0x63, 0xaa}
	h := MD5Hasher{Salt: &salt, Iter: &iter, Password: &password}

	check := h.Check("password")
	assert.Truef(t, check, "Passwords are equal")

	check = h.Check("password2")
	assert.Falsef(t, check, "Passwords are not equal")
}

func TestMD5Hasher_Hash(t *testing.T) {
	salt := "salt"
	iter := 1
	password := []byte{0x67, 0xa1, 0xe0, 0x9b, 0xb1, 0xf8, 0x3f, 0x50, 0x07, 0xdc, 0x11, 0x9c, 0x14, 0xd6, 0x63, 0xaa}
	h := MD5Hasher{Salt: &salt, Iter: &iter}

	g := h.Hash("password")
	assert.Equal(t, password, g)
}

func TestMD5Hasher_Hash_Empty(t *testing.T) {
	h := MD5Hasher{}
	h.Hash("password")
	assert.NotNil(t, h.Iter)
	assert.NotNil(t, h.Salt)
}

func TestMD5Hasher_SetPassword(t *testing.T) {
	h := MD5Hasher{}
	h.SetPassword("password")
	assert.NotNil(t, h.Password)
}
