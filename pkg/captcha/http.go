package captcha

import "net/http"

type HTTP interface {
	Do(req *http.Request) (*http.Response, error)
}
