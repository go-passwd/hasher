package hasher

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var strPassword = "plain$password"

func TestNew(t *testing.T) {
	g, e := New(TypePlain, nil, nil, nil)
	assert.Nil(t, e)
	assert.IsType(t, &PlainHasher{}, g)

	g, e = New(TypeMD5, nil, nil, nil)
	assert.Nil(t, e)
	assert.IsType(t, &MD5Hasher{}, g)

	g, e = New(TypeSHA1, nil, nil, nil)
	assert.Nil(t, e)
	assert.IsType(t, &SHA1Hasher{}, g)

	g, e = New(TypeSHA224, nil, nil, nil)
	assert.Nil(t, e)
	assert.IsType(t, &SHA224Hasher{}, g)

	g, e = New(TypeSHA256, nil, nil, nil)
	assert.Nil(t, e)
	assert.IsType(t, &SHA256Hasher{}, g)

	g, e = New(TypeSHA384, nil, nil, nil)
	assert.Nil(t, e)
	assert.IsType(t, &SHA384Hasher{}, g)

	g, e = New(TypeSHA512, nil, nil, nil)
	assert.Nil(t, e)
	assert.IsType(t, &SHA512Hasher{}, g)

	g, e = New(TypeSHA512_224, nil, nil, nil)
	assert.Nil(t, e)
	assert.IsType(t, &SHA512_224Hasher{}, g)

	g, e = New(TypeSHA512_256, nil, nil, nil)
	assert.Nil(t, e)
	assert.IsType(t, &SHA512_256Hasher{}, g)

	g, e = New("unsupported", nil, nil, nil)
	assert.Nil(t, g)
	assert.Errorf(t, e, "Unsupported hasher unsupported")
}
