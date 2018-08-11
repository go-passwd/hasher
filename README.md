# Password hasher library for Go

[![Build Status](https://travis-ci.org/tomi77/go-passwd.svg?branch=master)](https://travis-ci.org/tomi77/go-passwd)
[![Coverage Status](https://coveralls.io/repos/github/tomi77/go-passwd/badge.svg?branch=master)](https://coveralls.io/github/tomi77/go-passwd?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/tomi77/go-passwd)](https://goreportcard.com/report/github.com/tomi77/go-passwd)
[![GoDoc](https://godoc.org/github.com/tomi77/go-passwd/passwd?status.svg)](https://godoc.org/github.com/tomi77/go-passwd/passwd)

## Installation

~~~sh
go get -u github.com/tomi77/go-passwd/passwd
~~~

## Usage

~~~go
hshr := hasher.New(hasher.TypeSHA512)
hshr.SetPassword(plainTextPassword)
hashedPassword := hshr.String()
~~~

## Hashers

### PlainHasher

Stored password as plain text.

~~~go
passwordHasher := hasher.New(hasher.TypePlain)
~~~

### MD5Hasher

Store password as MD5 hash.

~~~go
passwordHasher := hasher.New(hasher.TypeMD5)
~~~

### SHA1Hasher

Store password as SHA-1 hash.

~~~go
passwordHasher := hasher.New(hasher.TypeSHA1)
~~~

### SHA224Hasher

Store password as SHA-224 hash.

~~~go
passwordHasher := hasher.New(hasher.TypeSHA224)
~~~

### SHA256Hasher

Store password as SHA-256 hash.

~~~go
passwordHasher := hasher.New(hasher.TypeSHA256)
~~~

### SHA384Hasher

Store password as SHA-384 hash.

~~~go
passwordHasher := hasher.New(hasher.TypeSHA384)
~~~

### SHA512Hasher

Store password as SHA-512 hash.

~~~go
passwordHasher := hasher.New(hasher.TypeSHA512)
~~~

### SHA512_224Hasher

Store password as SHA-512/224 hash.

~~~go
passwordHasher := hasher.New(hasher.TypeSHA512_224)
~~~

### SHA512_256Hasher

Store password as SHA-512/256 hash.

~~~go
passwordHasher := hasher.New(hasher.TypeSHA512_256)
~~~
