package fluentbitconfig

import (
	"bytes"
	"strings"
	"text/template"
)

type (
	Config struct {
		Service  Service
		Input    []Input
		Filter   []Filter
		Output   []Output
		Includes []Include
	}

	Service map[string]string
	Input   map[string]string
	Filter  map[string]string
	Output  map[string]string
	Include string
)

var t = func() *template.Template {
	t, err := template.New("").Funcs(template.FuncMap{
		"trim": strings.TrimSpace,
	}).Parse(`
{{ if .Service }}
[SERVICE]
{{- range $key, $value := .Service }}
    {{ $key | trim }} {{ $value | trim }}{{ end }}{{ end }}
{{ range $input := .Input }}
[INPUT]
{{- range $key, $value := $input }}
    {{ $key | trim }} {{ $value | trim }}{{ end }}{{ end }}
{{ range $filter := .Filter }}
[FILTER]
{{- range $key, $value := $filter }}
    {{ $key | trim }} {{ $value | trim }}{{ end }}{{ end }}
{{ range $output := .Output }}
[OUTPUT]
{{- range $key, $value := $output }}
    {{ $key | trim }} {{ $value | trim }}{{ end }}{{ end }}

{{ range $include := .Includes }}@INCLUDE {{ $include }}{{ end }}
`)
	if err != nil {
		panic(err)
	}

	return t
}()

func (c Config) Generate() string {
	var buf bytes.Buffer
	err := t.Execute(&buf, c)
	if err != nil {
		// as this function is tested, this should never happen...
		panic(err)
	}

	return strings.TrimSpace(buf.String())
}
