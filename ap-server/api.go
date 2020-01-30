/*
 * Autopolicy PoC
 * Copyright (C) 2019-2020 IITiS PAN Gliwice <https://www.iitis.pl/>
 * Author: Pawel Foremski <pjf@iitis.pl>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

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
	S := a.S

	input, ok := ar.in.(map[string]interface{})
	if !ok { return ar.Err(http.StatusBadRequest, "invalid input", nil) }

	// convert
	id, err := S.NewIdentity(input)
	if err == nil { err = id.CheckRequired() }
	if err != nil { return ar.Err(http.StatusBadRequest, "invalid identity", err.Error()) }

	// verify it's not a downgrade attack
	id, err = S.db.Verify(id)
	if err != nil { return ar.Err(http.StatusForbidden, err.Error(), nil) } // NB: permanent error

	// authorize, fetch the traffic profile
	pf, err := S.db.Authorize(id)
	if err != nil { return ar.Err(http.StatusServiceUnavailable, err.Error(), nil) } // NB: will retry
	
	ar.out = pf
	return ar
}
