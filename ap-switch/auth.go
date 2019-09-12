package main

import (
	"net"
	"math/rand"
	"time"
)

func now() int64 { return time.Now().Unix() }

// auth tries to move state from STATE_NEEDS_AUTH to STATE_ON
func (S *Switch) auth(st *State) {
	var ip net.IP

	// check starting point
	st.mutex.RLock()
	timeout := st.timeout
	state := st.state
	st.mutex.RUnlock()
	if state != STATE_NEEDS_AUTH || now() > timeout {
		dbg(0, "auth", "%s/%s: invalid starting point", st.iface, st.mac)
		return
	}

	// start authentication
	st.mutex.Lock()
	st.state = STATE_IN_AUTH
	st.since = now()
	st.timeout = st.timeout + AUTH_TIMEOUT
	st.mutex.Unlock()
	for i := 1; true; i++ {
		st.mutex.Lock()
		timeout = st.timeout
		state = st.state
		ip = append(ip, st.lastip...)
		st.mutex.Unlock()

		if state != STATE_IN_AUTH || now() > timeout {
			dbg(1, "auth", "%s/%s: aborting authentication (try %d)", st.iface, st.mac, i)
			return
		}

		// TODO: curl it!
		dbg(3, "auth", "%s/%s: authenticating on IP %s (try %d)", st.iface, st.mac, ip, i)

		// TODO
		break // success!

		time.Sleep(time.Second * AUTH_RETRY_TIMEOUT)
	}
	dbg(1, "auth", "%s/%s: authenticated", st.iface, st.mac)

	// start authorization
	st.mutex.Lock()
	st.state = STATE_IN_AUTHZ
	st.since = now()
	st.timeout = st.since + AUTHZ_TIMEOUT
	st.mutex.Unlock()
	for i := 1; true; i++ {
		st.mutex.Lock()
		timeout = st.timeout
		state = st.state
		st.mutex.Unlock()

		if state != STATE_IN_AUTHZ || now() > timeout {
			dbg(1, "auth", "%s/%s: aborting authorization (try %d)", st.iface, st.mac, i)
			return
		}

		// TODO: curl it!
		dbg(3, "auth", "%s/%s: authorizing (try %d)", st.iface, st.mac, i)

		// TODO
		break // success!

		time.Sleep(time.Second * AUTHZ_RETRY_TIMEOUT)
	}
	dbg(1, "auth", "%s/%s: authorized", st.iface, st.mac)

	// start provisioning
	st.mutex.Lock()
	st.state = STATE_IN_PROV
	st.since = now()
	st.timeout = st.since + PROV_TIMEOUT
	st.mutex.Unlock()
	for i := 1; true; i++ {
		st.mutex.Lock()
		timeout = st.timeout
		state = st.state
		st.mutex.Unlock()

		if state != STATE_IN_PROV || now() > timeout {
			dbg(1, "auth", "%s/%s: aborting provisioning", st.iface, st.mac)
			return
		}

		// TODO
		dbg(3, "auth", "%s/%s: provisioning (try %d)", st.iface, st.mac, i)
		err := tc_provision(st.iface, st.mac)

		// success?
		if err == nil {
			break
		}

		// error
		dbg(2, "auth", "%s/%s: provision error: %s", st.iface, st.mac, err)
		time.Sleep(time.Second * PROV_RETRY_TIMEOUT)
	}
	dbg(1, "auth", "%s/%s: provisioned", st.iface, st.mac)

	// mark port as done
	st.mutex.Lock()
	st.state = STATE_ON
	st.since = now()
	st.timeout = st.since + 3600 + rand.Int63n(82800) // will do a re-auth after random 1-24h delay
	st.mutex.Unlock()
}
