package main

import (
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
	err_auth_state = errors.New("invalid state")
	err_auth_timeout = errors.New("timeout")
	err_auth_json = errors.New("JSON error")
)

// auth tries to move state from STATE_NEEDS_AUTH to STATE_ON
func (S *Switch) auth(st *State) {
	var identity, profile map[string]interface{}
	var err error
	tag := st.tag

	dbg(1, "auth", "%s: starting auth", tag)

	// check starting point
	st.mutex.RLock()
	timeout := st.timeout
	state := st.state
	st.mutex.RUnlock()
	if state != STATE_NEEDS_AUTH || nanotime() > timeout {
		dbg(0, "auth", "%s: invalid starting point", tag)
		return
	}

	// authenticate
	st.auth_move_state(STATE_IN_AUTH, AUTH_TIMEOUT)
	for i := 1; identity == nil; i++ {
		identity, err = S.auth_authenticate(st)
		switch err {
		case nil:
			dbg(2, "auth", "%s: authenticated: %#v", tag, identity)
		case err_auth_timeout:
			dbg(2, "auth", "%s: authentication timeout: will use empty identity", tag)
		default:
			dbg(2, "auth", "%s: authentication failed (try %d): %s", tag, i, err)
			time.Sleep(AUTH_RETRY_TIMEOUT)
		}
	}

	// authorize
	st.auth_move_state(STATE_IN_AUTHZ, AUTHZ_TIMEOUT)
	for i := 1; profile == nil; i++ {
		profile, err = S.auth_authorize(st, identity)
		switch err {
		case nil:
			dbg(2, "auth", "%s: authorized: %#v", tag, profile)
		case err_auth_timeout:
			dbg(2, "auth", "%s: authorization timeout: aborting", tag)
			return
		default:
			dbg(2, "auth", "%s: authorization failed (try %d): %s", tag, i, err)
			time.Sleep(AUTHZ_RETRY_TIMEOUT)
		}
	}

	// start provisioning
	st.auth_move_state(STATE_IN_PROV, PROV_TIMEOUT)
	for i := 1; i == 1 || err != nil; i++ {
		err = S.auth_provision(st, profile)
		switch err {
		case nil:
			dbg(2, "auth", "%s: provisioned", tag)
		case err_auth_timeout:
			dbg(2, "auth", "%s: provisioning timeout: aborting", tag)
			return
		default:
			dbg(2, "auth", "%s: provisioning failed (try %d): %s", tag, i, err)
			time.Sleep(PROV_RETRY_TIMEOUT)
		}
	}

	// mark port as done, will re-auth after random 1-24h delay
	st.auth_move_state(STATE_ON, (3600 + rand.Int63n(82800)) * 1e9)
}

func (st *State) auth_move_state(state int, timeout int64) {
	st.mutex.Lock()
	st.state = state
	st.since = nanotime()
	st.timeout = st.since + timeout
	st.mutex.Unlock()
}

func (S *Switch) auth_compile_target(template *fasttemplate.Template, st *State, lastip net.IP) string {
	return template.ExecuteFuncString(fasttemplate.TagFunc(
	func (w io.Writer, tag string) (int, error) {
		var val string

		switch tag {
		case "ip":      val = lastip.String()
		case "iface":   val = st.iface
		case "mac":     val = st.mac.String()

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

func (S *Switch) auth_identity_ammend(identity map[string]interface{}, st *State, lastip net.IP) {
	identity["timestamp"] = time.Now().Unix()
	identity["me"] = S.opts.me
	identity["iface"] = st.iface
	identity["mac"] = st.mac.String()
	identity["lastip"] = lastip.String()
}

func (S *Switch) auth_authenticate(st *State) (
	identity map[string]interface{},
	err error,
) {
	// copy state
	st.mutex.RLock()
	timeout := st.timeout
	state := st.state
	lastip := append(net.IP(nil), st.lastip...)
	st.mutex.RUnlock()

	if state != STATE_IN_AUTH { return nil, err_auth_state }

	// create empty identity
	identity = make(map[string]interface{})

	// after timeout? well, that's what we've got
	if nanotime() > timeout {
		S.auth_identity_ammend(identity, st, lastip)
		return identity, err_auth_timeout
	}

	// where to fetch the identity from?
	target := S.auth_compile_target(S.auth_query, st, lastip)

	// curl it! ;)
	dbg(4, "auth", "%s: fetching identity from %s", st.tag, target)
	var identity_bytes []byte
	identity_bytes, err = S.http_get(target)
	if err != nil { return nil, err }

	// parse
	err = json.Unmarshal(identity_bytes, &identity)
	if err != nil { return nil, fmt.Errorf("JSON parser: %s in: %s", err, string(identity_bytes)) }

	// ammend
	S.auth_identity_ammend(identity, st, lastip)
	return
}

func (S *Switch) auth_authorize(st *State, identity map[string]interface{}) (
	profile map[string]interface{},
	err error,
) {
	// copy state
	st.mutex.RLock()
	timeout := st.timeout
	state := st.state
	lastip := append(net.IP(nil), st.lastip...)
	st.mutex.RUnlock()

	switch {
	case state != STATE_IN_AUTHZ: return nil, err_auth_state
	case nanotime() > timeout:    return nil, err_auth_timeout
	}

	// where to fetch the profile from?
	target := S.auth_compile_target(S.authz_query, st, lastip)

	// encode the identity back to JSON
	var identity_bytes []byte
	identity_bytes, err = json.Marshal(identity)
	if err != nil { return }

	// curl it!
	dbg(4, "auth", "%s: fetching profile from %s", st.tag, target)
	var profile_bytes []byte
	profile_bytes, err = S.http_post(target, identity_bytes)
	if err != nil { return nil, err }

	// parse
	profile = make(map[string]interface{})
	err = json.Unmarshal(profile_bytes, &profile)
	if err != nil { return nil, fmt.Errorf("JSON parser: %s in: %s", err, string(profile_bytes)) }

	// ammend
	profile["timestamp"] = time.Now().Unix()

	return
}

func (S *Switch) auth_provision(st *State, profile map[string]interface{}) error {
	// copy state
	st.mutex.RLock()
	timeout := st.timeout
	state := st.state
	st.mutex.RUnlock()

	switch {
	case state != STATE_IN_PROV: return err_auth_state
	case nanotime() > timeout:   return err_auth_timeout
	}

	return S.tc_provision(st, profile)
}
