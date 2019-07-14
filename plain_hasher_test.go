package hasher

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPlainHasher_String(t *testing.T) {
	h := PlainHasher{}
	h.SetPassword("password")

	w := "password"
	g := h.String()
	assert.Equal(t, w, g)

	h = PlainHasher{}
	assert.Panics(t, assert.PanicTestFunc(func() {
		_ = h.String()
	}))
}

func TestPlainHasher_Check(t *testing.T) {
	h := PlainHasher{}
	h.SetPassword("password")

	check := h.Check("password")
	assert.Truef(t, check, "Passwords are equal")

	check = h.Check("password2")
	assert.Falsef(t, check, "Passwords are not equal")
}

func TestPlainHasher_Hash(t *testing.T) {
	h := PlainHasher{}

	g := h.Hash("password")
	assert.Equal(t, []byte("password"), g)
}

func TestPlainHasher_SetPassword(t *testing.T) {
	h := PlainHasher{}
	h.SetPassword("password")
	assert.NotNil(t, h.Password)
}
