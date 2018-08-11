package hasher

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

var strPassword = "plain$password"

func ExampleNewHasherFromString() {
	h, err := NewHasherFromString(strPassword)
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println(h.Code())
	// Output:
	// plain
}

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

func TestNewFromString_Plain(t *testing.T) {
	g, e := NewHasherFromString("plain$pass")
	assert.Nil(t, e)
	assert.IsType(t, &PlainHasher{}, g)
}

func TestNewFromString_MD5(t *testing.T) {
	g, e := NewHasherFromString("md5$1$salt$pass")
	assert.Nil(t, e)
	assert.IsType(t, &MD5Hasher{}, g)
}

func TestNewFromString_SHA1(t *testing.T) {
	g, e := NewHasherFromString("sha1$1$salt$pass")
	assert.Nil(t, e)
	assert.IsType(t, &SHA1Hasher{}, g)
}

func TestNewFromString_SHA224(t *testing.T) {
	g, e := NewHasherFromString("sha224$1$salt$pass")
	assert.Nil(t, e)
	assert.IsType(t, &SHA224Hasher{}, g)
}

func TestNewFromString_SHA256(t *testing.T) {
	g, e := NewHasherFromString("sha256$1$salt$pass")
	assert.Nil(t, e)
	assert.IsType(t, &SHA256Hasher{}, g)
}

func TestNewFromString_SHA384(t *testing.T) {
	g, e := NewHasherFromString("sha384$1$salt$pass")
	assert.Nil(t, e)
	assert.IsType(t, &SHA384Hasher{}, g)
}

func TestNewFromString_SHA512(t *testing.T) {
	g, e := NewHasherFromString("sha512$1$salt$pass")
	assert.Nil(t, e)
	assert.IsType(t, &SHA512Hasher{}, g)
}

func TestNewFromString_SHA512_224(t *testing.T) {
	g, e := NewHasherFromString("sha512_224$1$salt$pass")
	assert.Nil(t, e)
	assert.IsType(t, &SHA512_224Hasher{}, g)
}

func TestNewFromString_SHA512_256(t *testing.T) {
	g, e := NewHasherFromString("sha512_256$1$salt$pass")
	assert.Nil(t, e)
	assert.IsType(t, &SHA512_256Hasher{}, g)
}

func TestNewFromString_bad_hasher(t *testing.T) {
	g, e := NewHasherFromString("qaz123$1")
	assert.NotNil(t, e)
	assert.Nil(t, g)
}
