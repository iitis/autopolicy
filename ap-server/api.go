package main

import (
	// "fmt"
	"io"
	"net/http"
	"net/url"
	"encoding/json"
	"github.com/julienschmidt/httprouter"
	// "google.golang.org/genproto/googleapis/rpc/code"
)

type (
	Api struct {
    	S        *Server
   		rt       *httprouter.Router
	}

	ApiRequest struct {
		api     *Api
		resp    http.ResponseWriter
		req     *http.Request

		param   map[string]string // URI params
		query   url.Values        // query params
		in      interface{}       // input JSON (unmarshalled)

		status  int               // HTTP status code
		out     interface{}       // output JSON (will be marshalled)

		written bool
	}

	ApiHandler func(req *ApiRequest) *ApiRequest
)

func NewApi(S *Server) *Api {
    var a Api

    a.S = S

	a.rt = httprouter.New()
	a.rt.POST("/v1/authorize", a.Wrap(a.Authorize))

    return &a
}

func (a *Api) ServeHttp(addr string) {
	dbg(1, "api", "starting HTTP API at http://%s/", addr)
	dbgErr(0, "api", http.ListenAndServe(addr, a.rt))
	a.S.wg.Done()
}

func (a *Api) Wrap(handler ApiHandler) httprouter.Handle {
	return func(resp http.ResponseWriter, req *http.Request, p httprouter.Params) {
		var err error
		var ar ApiRequest

		// params
		ar.param = make(map[string]string)
		for i := range p {
			ar.param[p[i].Key], err = url.QueryUnescape(p[i].Value)
			if err != nil {
				ar.Err(http.StatusBadRequest, "URL parse error", err).Write()
				return
			}
		}

		// query params
		if len(req.URL.RawQuery) > 0 {
			ar.query, err = url.ParseQuery(req.URL.RawQuery)
			if err != nil {
				ar.Err(http.StatusBadRequest, "URL query parse error", err).Write()
				return
			}
		}

		// JSON
		if req.Method != "GET" {
			err := json.NewDecoder(req.Body).Decode(&ar.in)
			if err != nil && err != io.EOF {
				ar.Err(http.StatusBadRequest, "JSON parse error", err).Write()
				return
			}
		}

		// handler
		ar.api = a
		ar.resp = resp
		ar.req = req
		ar.status = http.StatusOK
		handler(&ar).Write()
	}
}

func (ar *ApiRequest) Write() *ApiRequest {
	if !ar.written {
		ar.resp.Header().Set("Content-Type", "application/json")
		ar.resp.WriteHeader(ar.status)
		json.NewEncoder(ar.resp).Encode(ar.out)
		ar.written = true
	}
	return ar
}

func (ar *ApiRequest) Err(status int, message string, details interface{}) *ApiRequest {
	ar.out = map[string]interface{}{
		"error": map[string]interface{} {
			"code":   3,
			"status": "INVALID_ARGUMENT",
			"message": message,
			"details": details,
		},
	}
	ar.status = status
	return ar
}

func (a *Api) Authorize(ar *ApiRequest) *ApiRequest {
	input, ok := ar.in.(map[string]interface{})
	if !ok { return ar.Err(http.StatusBadRequest, "invalid input", nil) }

	// convert
	id, err := NewIdentity(a.S, input)
	if err != nil { return ar.Err(http.StatusBadRequest, "invalid identity", err.Error()) }

	// authorize
	if err := a.S.db.Authorize(id); err != nil {
		return ar.Err(http.StatusForbidden, err.Error(), nil)
	}

	// mock profile
	profile := make(map[string]interface{})
	profile["id"] = id
	
	ar.out = profile
	return ar
}
