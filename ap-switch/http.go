package main

import (
	"encoding/json"
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

func (S *Switch) http_get(url string) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(S.ctx, HTTP_TIMEOUT)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil { return nil, -1, err }

	resp, err := S.http.Do(req)
	if err != nil { return nil, -1, err }
	defer resp.Body.Close()

	bytes, err := ioutil.ReadAll(resp.Body)
	return bytes, resp.StatusCode, err
}

func (S *Switch) http_post_json(url string, data interface{}) (interface{}, int, error) {
	ctx, cancel := context.WithTimeout(S.ctx, HTTP_TIMEOUT)
	defer cancel()

	// prepare
	databytes, err := json.Marshal(data)
	if err != nil { return nil, -1, err }

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(databytes))
	if err != nil { return nil, -2, err }

	// do the query
	req.Header.Set("Content-Type", "application/json")
	resp, err := S.http.Do(req)
	if err != nil { return nil, -3, err }
	defer resp.Body.Close()

	// decode
	bodybytes, err := ioutil.ReadAll(resp.Body)
	if err != nil || len(bodybytes) == 0 { return nil, resp.StatusCode, err }

	var body interface{}
	err = json.Unmarshal(bodybytes, &body)
	if err != nil { return bodybytes, resp.StatusCode, err }

	return body, resp.StatusCode, nil
}
