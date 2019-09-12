package main

import (
	"time"
	"fmt"
	"sync"
	"net"
	"flag"
)

const (
	AUTH_TIMEOUT = 300           // authentication timeout (in seconds)
	AUTH_RETRY_TIMEOUT = 10      // how quickly to retry auth attempts

	AUTHZ_TIMEOUT = 30           // authorization timeout (in seconds)
	AUTHZ_RETRY_TIMEOUT = 1      // how quickly to retry authz attempts

	PROV_TIMEOUT = 3            // provision timeout (in seconds)
	PROV_RETRY_TIMEOUT = 1       // how quickly to retry provision attempts
)

type Switch struct {
	opts struct {
		dbg            int
		// --
		ifaces         []string
	}
	
	snifferq           chan SnifferMsg         // MAC-IP sniffer output
	state              map[string]*State       // port-MAC states
}

type State struct {
	mutex       sync.RWMutex
	
	// host identifiers
	iface       string
	mac         net.HardwareAddr
	lastip      net.IP

	// status
	state       int         // current state
	since       int64       // UNIX timestamp of last state update
	timeout     int64       // UNIX timestamp when current state times out
}

const (
	STATE_OFF        = iota // port is off
	STATE_NEEDS_AUTH        // needs authentication
	STATE_IN_AUTH           // doing authentication
	STATE_AUTHENTICATED     // authentication done
	STATE_IN_AUTHZ          // doing authorization
	STATE_AUTHORIZED        // authorization done
	STATE_IN_PROV           // doing provision
	STATE_ON                // network access provisioned
)

func main() {
	var S Switch

	// command-line args
	flag.IntVar(&S.opts.dbg, "dbg", 2, "debugging level")

	flag.Parse()
	dbgSet(S.opts.dbg)
	S.opts.ifaces = flag.Args()

	// start sniffers
	if len(S.opts.ifaces) == 0 {
		die("main", "no interfaces given on command-line")
	}

	S.snifferq = make(chan SnifferMsg, 100)
	for _, iface := range S.opts.ifaces {
		// prepare tc
		tc_cleanup(iface)
		if err := tc_init(iface); err != nil {
			die("main", "tc setup: %s", err)
		}

		dbg(1, "main", "starting sniffer on %s", iface)
		go S.sniffer(iface)
	}

	// read from sniffers
	S.state = make(map[string]*State)
	for msg := range S.snifferq {
		dbg(3, "main", "sniffer: seen PORT/MAC/IP: %s/%s/%s", msg.iface, msg.mac, msg.ip)

		// need to authenticate?
		key := fmt.Sprintf("%s/%s", msg.iface, msg.mac)
		st, ok := S.state[key]
		if !ok { // yes, new stuff, needs auth
			dbg(2, "main", "new PORT/MAC %s/%s (%s)", msg.iface, msg.mac, msg.ip)

			st = &State{}
			st.mutex.Lock()
			st.iface = msg.iface
			st.mac = msg.mac
			st.lastip = msg.ip

			S.state[key] = st
		} else { // lets check...
			st.mutex.Lock()

			// BTW, update IP if needed
			if !st.lastip.Equal(msg.ip) {
				dbg(2, "main", "%s/%s: updating IP address: %s -> %s (state %d)",
					st.iface, st.mac, st.lastip, msg.ip, st.state)
				st.lastip = msg.ip
			}

			// before timeout? no, leave it
			now := time.Now().Unix()
			if now < st.timeout {
				st.mutex.Unlock()
				continue
			}

			dbg(2, "main", "%s/%s: port state %d timeout after %ds",
				msg.iface, msg.mac, st.state, now - st.timeout)
		}

		// authentication needed
		st.state = STATE_NEEDS_AUTH
		st.since = time.Now().Unix()
		st.timeout = st.since + 5 // give it 5 sec
		st.mutex.Unlock()

		// request authentication
		dbg(1, "main", "%s/%s: requesting authentication via IP %s", st.iface, st.mac, st.lastip)
		go S.auth(st)
	}
}
