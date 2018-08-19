package hasher

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
)

// HexMarshaler stores password in HEX
type HexMarshaler struct {
	Separator string
}

// Marshal Hasher to string
func (m *HexMarshaler) Marshal(h Hasher) (string, error) {
	var params templateParams
	switch h.Code() {
	case TypePlain:
		hh := h.(*PlainHasher)
		params = templateParams{
			Code:       h.Code(),
			Iterations: 0,
			Salt:       "",
			Password:   hex.EncodeToString(*hh.Password),
		}
	case TypeMD5:
		hh := h.(*MD5Hasher)
		params = templateParams{
			Code:       h.Code(),
			Iterations: *hh.Iter,
			Salt:       *hh.Salt,
			Password:   hex.EncodeToString(*hh.Password),
		}
	case TypeSHA1:
		hh := h.(*SHA1Hasher)
		params = templateParams{
			Code:       h.Code(),
			Iterations: *hh.Iter,
			Salt:       *hh.Salt,
			Password:   hex.EncodeToString(*hh.Password),
		}
	case TypeSHA224:
		hh := h.(*SHA224Hasher)
		params = templateParams{
			Code:       h.Code(),
			Iterations: *hh.Iter,
			Salt:       *hh.Salt,
			Password:   hex.EncodeToString(*hh.Password),
		}
	case TypeSHA256:
		hh := h.(*SHA256Hasher)
		params = templateParams{
			Code:       h.Code(),
			Iterations: *hh.Iter,
			Salt:       *hh.Salt,
			Password:   hex.EncodeToString(*hh.Password),
		}
	case TypeSHA384:
		hh := h.(*SHA384Hasher)
		params = templateParams{
			Code:       h.Code(),
			Iterations: *hh.Iter,
			Salt:       *hh.Salt,
			Password:   hex.EncodeToString(*hh.Password),
		}
	case TypeSHA512:
		hh := h.(*SHA512Hasher)
		params = templateParams{
			Code:       h.Code(),
			Iterations: *hh.Iter,
			Salt:       *hh.Salt,
			Password:   hex.EncodeToString(*hh.Password),
		}
	case TypeSHA512_224:
		hh := h.(*SHA512_224Hasher)
		params = templateParams{
			Code:       h.Code(),
			Iterations: *hh.Iter,
			Salt:       *hh.Salt,
			Password:   hex.EncodeToString(*hh.Password),
		}
	case TypeSHA512_256:
		hh := h.(*SHA512_256Hasher)
		params = templateParams{
			Code:       h.Code(),
			Iterations: *hh.Iter,
			Salt:       *hh.Salt,
			Password:   hex.EncodeToString(*hh.Password),
		}
	}
	params.Separator = m.Separator
	buf := bytes.NewBufferString("")
	err := marshalTemplate.ExecuteTemplate(buf, "marshalTemplate", params)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

// Unmarshal string to Hasher
func (m *HexMarshaler) Unmarshal(s string) (Hasher, error) {
	buf := bytes.NewBufferString("")
	params := templateParams{Separator: m.Separator}
	err := unmarshalPattern.ExecuteTemplate(buf, "unmarshalPattern", params)
	if err != nil {
		return nil, err
	}
	re := regexp.MustCompile(buf.String())
	submatch := re.FindStringSubmatch(s)
	if submatch == nil {
		return nil, fmt.Errorf("cannot unmarshal string %s", s)
	}

	password, err := hex.DecodeString(submatch[4])
	if err != nil {
		return nil, err
	}
	iter, err := strconv.Atoi(submatch[2])
	if err != nil {
		return nil, err
	}

	switch submatch[1] {
	case TypePlain:
		return &PlainHasher{
			Password: &password,
		}, nil
	case TypeMD5:
		return &MD5Hasher{
			Iter:     &iter,
			Salt:     &submatch[3],
			Password: &password,
		}, nil
	case TypeSHA1:
		return &SHA1Hasher{
			Iter:     &iter,
			Salt:     &submatch[3],
			Password: &password,
		}, nil
	case TypeSHA224:
		return &SHA224Hasher{
			Iter:     &iter,
			Salt:     &submatch[3],
			Password: &password,
		}, nil
	case TypeSHA256:
		return &SHA256Hasher{
			Iter:     &iter,
			Salt:     &submatch[3],
			Password: &password,
		}, nil
	case TypeSHA384:
		return &SHA384Hasher{
			Iter:     &iter,
			Salt:     &submatch[3],
			Password: &password,
		}, nil
	case TypeSHA512:
		return &SHA512Hasher{
			Iter:     &iter,
			Salt:     &submatch[3],
			Password: &password,
		}, nil
	case TypeSHA512_224:
		return &SHA512_224Hasher{
			Iter:     &iter,
			Salt:     &submatch[3],
			Password: &password,
		}, nil
	case TypeSHA512_256:
		return &SHA512_256Hasher{
			Iter:     &iter,
			Salt:     &submatch[3],
			Password: &password,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported hasher %s", submatch[1])
	}
}
