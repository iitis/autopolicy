package main

import (
	"net"
	"math/rand"
	"time"
)

// auth tries to move state from STATE_NEEDS_AUTH to STATE_ON
func (S *Switch) auth(st *State) {
	var ip net.IP
	var identity, profile []byte
	var err error

	// check starting point
	st.mutex.RLock()
	timeout := st.timeout
	state := st.state
	st.mutex.RUnlock()
	if state != STATE_NEEDS_AUTH || nanotime() > timeout {
		dbg(0, "auth", "%s/%s: invalid starting point", st.iface, st.mac)
		return
	}

	// start authentication
	st.mutex.Lock()
	st.state = STATE_IN_AUTH
	st.since = nanotime()
	st.timeout = st.timeout + AUTH_TIMEOUT
	st.mutex.Unlock()
	for i := 1; true; i++ {
		st.mutex.Lock()
		timeout = st.timeout
		state = st.state
		ip = ip[:0]
		ip = append(ip, st.lastip...)
		st.mutex.Unlock()

		if state != STATE_IN_AUTH || nanotime() > timeout {
			dbg(1, "auth", "%s/%s: aborting authentication (try %d)", st.iface, st.mac, i)
			return
		}

		// curl it! ;)
		dbg(3, "auth", "%s/%s: authenticating on IP %s (try %d)", st.iface, st.mac, ip, i)
		identity, err = S.http_get("http://" + ip.String() + "/.autopolicy/identity.json")
		if err == nil {
			// TODO: parse and ammend identity (me, iface, mac, ip)
			break
		} // success

		// retry
		dbg(2, "auth", "%s/%s: could not fetch identity: %s", st.iface, st.mac, err)
		time.Sleep(AUTH_RETRY_TIMEOUT)
	}
	dbg(1, "auth", "%s/%s: authenticated", st.iface, st.mac)

	// start authorization
	st.mutex.Lock()
	st.state = STATE_IN_AUTHZ
	st.since = nanotime()
	st.timeout = st.since + AUTHZ_TIMEOUT
	st.mutex.Unlock()
	for i := 1; true; i++ {
		st.mutex.Lock()
		timeout = st.timeout
		state = st.state
		st.mutex.Unlock()

		if state != STATE_IN_AUTHZ || nanotime() > timeout {
			dbg(1, "auth", "%s/%s: aborting authorization (try %d)", st.iface, st.mac, i)
			return
		}

		// curl it!
		dbg(3, "auth", "%s/%s: authorizing (try %d)", st.iface, st.mac, i)
		profile, err = S.http_post(S.opts.authserver + "/.autopolicy/v1/authorize", identity)
		if err == nil {
			println(string(profile))
			break  // success
		}

		// retry
		dbg(2, "auth", "%s/%s: could not authorize: %s", st.iface, st.mac, err)
		time.Sleep(AUTHZ_RETRY_TIMEOUT)
	}
	dbg(1, "auth", "%s/%s: authorized", st.iface, st.mac)

	// start provisioning
	st.mutex.Lock()
	st.state = STATE_IN_PROV
	st.since = nanotime()
	st.timeout = st.since + PROV_TIMEOUT
	st.mutex.Unlock()
	for i := 1; true; i++ {
		st.mutex.Lock()
		timeout = st.timeout
		state = st.state
		st.mutex.Unlock()

		if state != STATE_IN_PROV || nanotime() > timeout {
			dbg(1, "auth", "%s/%s: aborting provisioning", st.iface, st.mac)
			return
		}

		// TODO: use profile
		dbg(3, "auth", "%s/%s: provisioning (try %d)", st.iface, st.mac, i)
		err := S.tc_provision(st.iface, st.mac)

		// success?
		if err == nil {
			break
		}

		// error
		dbg(2, "auth", "%s/%s: provision error: %s", st.iface, st.mac, err)
		time.Sleep(PROV_RETRY_TIMEOUT)
	}
	dbg(1, "auth", "%s/%s: provisioned", st.iface, st.mac)

	// mark port as done
	st.mutex.Lock()
	st.state = STATE_ON
	st.since = nanotime()
	st.timeout = st.since + (3600 + rand.Int63n(82800)) * 1e9 // re-auth after random 1-24h delay
	st.mutex.Unlock()
}
