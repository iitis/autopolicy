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
	"net/http"
	"fmt"
	"encoding/json"
	"net/url"
	"io"
	"errors"
	"net"
	"math/rand"
	"time"
	"github.com/valyala/fasttemplate"
)

var (
	err_state = errors.New("invalid state")
	err_state_timeout = errors.New("timeout")
	err_state_json = errors.New("JSON error")
	err_http_200 = errors.New("HTTP status not 200 OK")
)

// state_start_auth tries to move state from STATE_NEEDS_AUTH to STATE_ON
func (S *Switch) state_start_auth(st *State) {
	var identity, profile map[string]interface{}
	var err error
	tag := st.tag

	dbg(1, "state", "%s: starting auth", tag)

	// check starting point
	st.mutex.RLock()
	timeout := st.timeout
	state := st.state
	st.mutex.RUnlock()
	if state != STATE_NEEDS_AUTH || nanotime() > timeout {
		dbg(0, "state", "%s: invalid starting point", tag)
		return
	}

	// authenticate
	st.state_move(STATE_IN_AUTH, AUTH_TIMEOUT)
	for i := 1; identity == nil; i++ {
		identity, err = S.state_authenticate(st)
		switch err {
		case nil:
			dbg(2, "state", "%s: authenticated: %#v", tag, identity)
		case err_state_timeout:
			dbg(2, "state", "%s: authentication timeout: will use empty identity", tag)
		default:
			dbg(2, "state", "%s: authentication failed (try %d): %s", tag, i, err)
			time.Sleep(AUTH_RETRY_TIMEOUT * 1e9)
		}
	}

	// authorize
	st.state_move(STATE_IN_AUTHZ, AUTHZ_TIMEOUT)
	for i := 1; profile == nil; i++ {
		profile, err = S.state_authorize(st, identity)
		switch err {
		case nil:
			dbg(2, "state", "%s: authorized: %#v", tag, profile)
		case err_state_timeout:
			dbg(2, "state", "%s: authorization timeout: aborting", tag)
			return
		default:
			if profile == nil {
				dbg(2, "state", "%s: authorization failed (try %d): %s", tag, i, err)
				time.Sleep(AUTHZ_RETRY_TIMEOUT * 1e9)
			} else {
				// access denied for next 5-15 min
				dbg(2, "state", "%s: access denied: %s", tag, err)
				st.state_move(STATE_OFF, 300 + rand.Int63n(600))
				return
			}
		}
	}

	// start provisioning
	st.state_move(STATE_IN_PROV, PROV_TIMEOUT)
	err = S.state_provision(st, profile)
	switch err {
	case nil:
		dbg(2, "state", "%s: provisioned", tag)
	case err_state_timeout:
		dbg(2, "state", "%s: provisioning timeout: aborting", tag)
		return
	default:
		dbg(2, "state", "%s: provisioning failed (ban for 1 minute): %s", tag, err)
		st.state_move(STATE_OFF, 60) // access denied for next 1 min
		return
	}

	// mark port as done, will re-auth after random 1-24h delay
	//st.state_move(STATE_ON, 3600 + rand.Int63n(82800))
	// TODO: temporary
	st.state_move(STATE_ON, 300)
}

func (st *State) state_move(state int, timeout int64) {
	st.mutex.Lock()
	st.state = state
	st.since = nanotime()
	st.timeout = st.since + timeout*1e9
	st.mutex.Unlock()
}

func (S *Switch) state_compile_target(template *fasttemplate.Template, st *State, lastip net.IP) string {
	return template.ExecuteFuncString(fasttemplate.TagFunc(
	func (w io.Writer, tag string) (int, error) {
		var val string

		switch tag {
		case "ip":      val = lastip.String()
		case "iface":   val = st.iface
		case "mac":     val = st.mac.String()
		case "me":      val = S.opts.me

		// special case
		case "ip-host":
			if ip4 := lastip.To4(); ip4 != nil {
				val = ip4.String()
			} else {
				val = "[" + lastip.String() + "]"
			}
			return w.Write([]byte(val))
		}

		return w.Write([]byte(url.QueryEscape(val)))
	}))
}

func (S *Switch) state_identity_ammend(identity map[string]interface{}, st *State, lastip net.IP) {
	identity["@switch"] = S.opts.me
	identity["@port"] = st.iface
	identity["@mac"] = st.mac.String()
	identity["@ip"] = lastip.String()
}

func (S *Switch) state_authenticate(st *State) (map[string]interface{}, error) {
	// copy state
	st.mutex.RLock()
	timeout := st.timeout
	state := st.state
	lastip := append(net.IP(nil), st.lastip...)
	st.mutex.RUnlock()

	if state != STATE_IN_AUTH { return nil, err_state }

	// create empty identity
	identity := make(map[string]interface{})

	// after timeout? well, just use what we've got
	if nanotime() > timeout {
		S.state_identity_ammend(identity, st, lastip)
		return identity, err_state_timeout
	}

	// where to fetch the identity from?
	target := S.state_compile_target(S.auth_query, st, lastip)

	// curl it! ;)
	dbg(4, "state", "%s: fetching identity from %s", st.tag, target)
	identity_bytes, status, err := S.http_get(target)
	if err != nil { return nil, err }
	if status != http.StatusOK { return nil, err_http_200 }

	// parse
	err = json.Unmarshal(identity_bytes, &identity)
	if err != nil { return nil, fmt.Errorf("JSON parser: %s in: %s", err, string(identity_bytes)) }

	// ammend
	S.state_identity_ammend(identity, st, lastip)
	return identity, nil
}

func (S *Switch) state_authorize(st *State, identity map[string]interface{}) (map[string]interface{}, error) {
	var ok bool

	// copy state
	st.mutex.RLock()
	timeout := st.timeout
	state := st.state
	lastip := append(net.IP(nil), st.lastip...)
	st.mutex.RUnlock()

	switch {
	case state != STATE_IN_AUTHZ: return nil, err_state
	case nanotime() > timeout:    return nil, err_state_timeout
	}

	// where to fetch the profile from?
	target := S.state_compile_target(S.authz_query, st, lastip)

	// curl it!
	dbg(4, "state", "%s: fetching profile from %s", st.tag, target)
	out, status, err := S.http_post_json(target, identity)
	if err != nil {
		switch {
		case out != nil:
			return nil, fmt.Errorf("HTTP status %d: invalid JSON: %s: %s", status, err, out)
		case status > 0:
			return nil, fmt.Errorf("HTTP status %d: no body: %s", status, err)	
		default:
			return nil, fmt.Errorf("HTTP error: %s", err)	
		}
	}	

	// received an object?
	profile, ok := out.(map[string]interface{})
	if !ok { return nil, fmt.Errorf("HTTP status %d: not an object: %s", status, out) }

	// status != 200 means authorization failed
	if status != http.StatusOK {
		if e, ok := profile["error"].(map[string]interface{}); ok {
			if d,ok := e["details"]; ok && d != nil {
				err = fmt.Errorf("%s (%v)", e["message"], d)
			} else {
				err = fmt.Errorf("%s", e["message"])
			}
		} else {
			err = fmt.Errorf("HTTP status %d: %s", profile)
		}

		// if 403 (HTTP Forbidden), make it permanent
		if status == 403 {
			return profile, err
		} else {
			return nil, err
		}
	}

	// ammend
	profile["@timestamp"] = time.Now().Unix()

	return profile, nil
}

func (S *Switch) state_provision(st *State, profile map[string]interface{}) error {
	// copy state
	st.mutex.RLock()
	timeout := st.timeout
	state := st.state
	st.mutex.RUnlock()

	switch {
	case state != STATE_IN_PROV: return err_state
	case nanotime() > timeout:   return err_state_timeout
	}

	// TODO: verify the profile, it comes "from Internet"

	return S.tc_provision(st, profile)
}
