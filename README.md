# go-passwd

[![Build Status](https://travis-ci.org/tomi77/go-passwd.svg?branch=master)](https://travis-ci.org/tomi77/go-passwd)
[![Coverage Status](https://coveralls.io/repos/github/tomi77/go-passwd/badge.svg?branch=master)](https://coveralls.io/github/tomi77/go-passwd?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/tomi77/go-passwd)](https://goreportcard.com/report/github.com/tomi77/go-passwd)
[![GoDoc](https://godoc.org/github.com/tomi77/go-passwd/passwd?status.svg)](https://godoc.org/github.com/tomi77/go-passwd/passwd)

Password library for Go

## Installation

~~~sh
go get -u github.com/tomi77/go-passwd/passwd
~~~

## Usage

~~~go
import "github.com/tomi77/go-passwd/passwd"
~~~

### Check password

~~~go
correct, err := passwd.Check(form.Password, db.Password)
~~~

where

* ``form.Password`` is a password from form
* ``db.Password`` is a password from DB

### Hash password

~~~go
hasher := passwd.NewSHA512Hasher()
hasher.SetPassword(plainTextPassword)
hashedPassword := hasher.String()
~~~

### Validate password

Use [validator](https://github.com/go-passwd/validator)

### Generate password

Use [randomstring](https://github.com/go-randomstring/randomstring)

## Hashers

### PlainHasher

Stored password as plain text.

~~~go
passwordHasher := passwd.NewPlainHasher()
~~~

### MD5Hasher

Store password as MD5 hash.

~~~go
passwordHasher := passwd.NewMD5Hasher()
~~~

### SHA1Hasher

Store password as SHA-1 hash.

~~~go
passwordHasher := passwd.NewSHA1Hasher()
~~~

### SHA224Hasher

Store password as SHA-224 hash.

~~~go
passwordHasher := passwd.NewSHA224Hasher()
~~~

### SHA256Hasher

Store password as SHA-256 hash.

~~~go
passwordHasher := passwd.NewSHA256Hasher()
~~~

### SHA384Hasher

Store password as SHA-384 hash.

~~~go
passwordHasher := passwd.NewSHA384Hasher()
~~~

### SHA512Hasher

Store password as SHA-512 hash.

~~~go
passwordHasher := passwd.NewSHA512Hasher()
~~~

### SHA512_224Hasher

Store password as SHA-512/224 hash.

~~~go
passwordHasher := passwd.NewSHA512_224Hasher()
~~~

### SHA512_256Hasher

Store password as SHA-512/256 hash.

~~~go
passwordHasher := passwd.NewSHA512_256Hasher()
~~~
