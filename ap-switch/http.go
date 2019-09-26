package main

import (
	"bytes"
	"io/ioutil"
	"time"
	"net/http"
	"context"
)

const (
	HTTP_TIMEOUT = 10e9
)

func (S *Switch) http_init() {
	// max 100 idle connections, kill them after 30s
	S.http.Transport = &http.Transport{
		MaxIdleConns:       100,
		IdleConnTimeout:    30 * time.Second,
	}

	// do not follow redirects
	S.http.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
}

func (S *Switch) http_get(url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(S.ctx, HTTP_TIMEOUT)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil { return nil, err }

	resp, err := S.http.Do(req)
	if err != nil { return nil, err }
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil { return nil, err }

	return body, nil
}

func (S *Switch) http_post(url string, data []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(S.ctx, HTTP_TIMEOUT)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
	if err != nil { return nil, err }

	resp, err := S.http.Do(req)
	if err != nil { return nil, err }
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil { return nil, err }

	return body, nil
}
