package template

import (
	_ "embed"
	"html/template"
	"net/http"
)

//go:embed html/captcha.html
var captchaHTML string

type ChallengePageData struct {
	Provider       string
	SiteKey        string
	ChallengeToken string
	CallbackURL    string
}

type Store struct {
	captchaTemplate *template.Template
}

// NewStore compiles the embedded templates into a *template.Template
func NewStore() (*Store, error) {
	tmpl, err := template.New("captcha").Parse(captchaHTML)
	if err != nil {
		return nil, err
	}

	return &Store{
		captchaTemplate: tmpl,
	}, nil
}

// RenderCaptcha renders the challenge page into an http.ResponseWriter
func (s *Store) RenderCaptcha(w http.ResponseWriter, data ChallengePageData) error {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	return s.captchaTemplate.Execute(w, data)
}
