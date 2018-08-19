package hasher

import "html/template"

// Marshaler vars
var (
	marshalTemplate  = template.Must(template.New("marshalTemplate").Parse("{{.Code}}{{.Separator}}{{.Iterations}}{{.Separator}}{{.Salt}}{{.Separator}}{{.Password}}"))
	unmarshalPattern = template.Must(template.New("unmarshalPattern").Parse("^(?P<code>\\w+)\\{{.Separator}}(?P<iterations>\\d+)\\{{.Separator}}(?P<salt>\\w*)\\{{.Separator}}(?P<password>\\w+)$"))
)

// Marshaler defines interface for marshal and unmarshal hasher
type Marshaler interface {
	Marshal(hshr Hasher) (string, error)

	Unmarshal(string) (Hasher, error)
}

// Marshaler template params struct
type templateParams struct {
	Code       string
	Iterations int
	Salt       string
	Password   string
	Separator  string
}
