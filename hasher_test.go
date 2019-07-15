package hasher

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var strPassword = "plain$password"

func TestNew(t *testing.T) {
	g, e := New(TypePlain)
	assert.Nil(t, e)
	assert.IsType(t, &PlainHasher{}, g)

	g, e = New(TypeMD5)
	assert.Nil(t, e)
	assert.IsType(t, &MD5Hasher{}, g)

	g, e = New(TypeSHA1)
	assert.Nil(t, e)
	assert.IsType(t, &SHA1Hasher{}, g)

	g, e = New(TypeSHA224)
	assert.Nil(t, e)
	assert.IsType(t, &SHA224Hasher{}, g)

	g, e = New(TypeSHA256)
	assert.Nil(t, e)
	assert.IsType(t, &SHA256Hasher{}, g)

	g, e = New(TypeSHA384)
	assert.Nil(t, e)
	assert.IsType(t, &SHA384Hasher{}, g)

	g, e = New(TypeSHA512)
	assert.Nil(t, e)
	assert.IsType(t, &SHA512Hasher{}, g)

	g, e = New(TypeSHA512_224)
	assert.Nil(t, e)
	assert.IsType(t, &SHA512_224Hasher{}, g)

	g, e = New(TypeSHA512_256)
	assert.Nil(t, e)
	assert.IsType(t, &SHA512_256Hasher{}, g)

	g, e = New("unsupported")
	assert.Nil(t, g)
	assert.Errorf(t, e, "Unsupported hasher unsupported")
}
