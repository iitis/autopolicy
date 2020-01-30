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
	"strings"
	"github.com/valyala/fasttemplate"
	"net/http"
	"os/signal"
	"os"
	"context"
	"fmt"
	"sync"
	"net"
	"flag"
)

const (
	VERSION = "0.1"

	AUTH_TIMEOUT = 60              // authentication timeout (in seconds)
	AUTH_RETRY_TIMEOUT = 19        // how quickly to retry auth attempts

	AUTHZ_TIMEOUT = 10             // authorization timeout (in seconds)
	AUTHZ_RETRY_TIMEOUT = 3        // how quickly to retry authz attempts

	PROV_TIMEOUT = 3               // provision timeout (in seconds)
	PROV_RETRY_TIMEOUT = 1         // how quickly to retry provision attempts
)

type Switch struct {
	ctx      context.Context
	hostname string
	http     http.Client

	opts struct {
		dbg            int
		me             string
		// --
		ifaces         []string
		// --
		auth_query     string
		authz_query    string
	}
	
	tcpref             int                     // global TC preference counter
	snifferq           chan SnifferMsg         // MAC-IP sniffer output
	state              map[string]*State       // port-MAC states

	auth_query         *fasttemplate.Template
	authz_query        *fasttemplate.Template
}

// State represents device state
type State struct {
	mutex       sync.RWMutex
	
	// host identifiers (immutable)
	iface       string
	mac         net.HardwareAddr
	tag         string      // human-readable id
	tc_chain    string

	// status (mutable)
	lastip      net.IP      // last seen IP address
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

func (S *Switch) sigint() {
	sigch := make(chan os.Signal, 1)
	signal.Notify(sigch, os.Interrupt)

	<-sigch // wait for SIGINT
	dbg(1, "main", "SIGINT received, cleanup and exit...")

	for _, iface := range S.opts.ifaces {
		S.tc_cleanup(iface) // ignore errors	
	}

	os.Exit(0)
}

func main() {
	var err error

	var S Switch
	S.ctx = context.Background()
	S.hostname, err = os.Hostname()
	if err != nil { dieErr("main", err) }

	// command-line args
	flag.IntVar(&S.opts.dbg, "dbg", 2, "debugging level")
	flag.StringVar(&S.opts.me, "me", S.hostname, "my identity, e.g. name of this host")
	flag.StringVar(&S.opts.auth_query, "query", "http://<ip>/.autopolicy/identity.json",
		"authentication query (HTTP GET) used to fetch the identity")
	flag.StringVar(&S.opts.authz_query, "authz", "http://192.168.100.128:30000/v1/authorize",
		"authorization query (HTTP POST) used to fetch the profile")

	flag.Parse()
	dbgSet(S.opts.dbg)

	// read interfaces
	S.opts.ifaces = flag.Args()
	if len(S.opts.ifaces) == 0 { die("main", "no interfaces given on command-line") }

	// parse templates
	q := strings.Replace(S.opts.auth_query, "://<ip>", "://<ip-host>", 1)
	S.auth_query, err = fasttemplate.NewTemplate(q, "<", ">")
	if err != nil { die("main", "-query template invalid: %s", err) }

	q = strings.Replace(S.opts.authz_query, "://<ip>", "://<ip-host>", 1)
	S.authz_query, err = fasttemplate.NewTemplate(q, "<", ">")
	if err != nil { die("main", "-authz template invalid: %s", err) }

	// start
	dbg(1, "main", "ap-switch %s starting on %s", VERSION, S.hostname)
	dbg(2, "main", "command-line options: %#v", S.opts)

	// handle SIGINT
	go S.sigint()

	// prepare tc
	S.tcpref = 1
	for _, iface := range S.opts.ifaces {
		S.tc_cleanup(iface) // ignore errors
		if err := S.tc_init(iface); err != nil {
			S.tc_cleanup(iface) // ignore errors
			die("main", "tc setup failed: %s", err)
		}
	}

	S.http_init()

	// -------------------------------------

	// start sniffers
	S.snifferq = make(chan SnifferMsg, 100)
	for _, iface := range S.opts.ifaces {
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
			st = &State{}
			st.mutex.Lock()
			st.iface = msg.iface
			st.mac = msg.mac
			st.lastip = msg.ip
			st.tc_chain = fmt.Sprintf("%d", len(S.state) + 1)
			st.tag = fmt.Sprintf("[%s/%s]", st.iface, st.mac)

			dbg(3, "main", "%s: new PORT/MAC using IP %s", st.tag, st.lastip)

			S.state[key] = st
		} else { // lets check...
			st.mutex.Lock()

			// BTW, update IP if needed
			if !st.lastip.Equal(msg.ip) {
				dbg(2, "main", "%s: updating IP address: %s -> %s (state %d)",
					st.tag, st.lastip, msg.ip, st.state)
				st.lastip = msg.ip
			}

			// before timeout? no, leave it
			now := nanotime()
			if now < st.timeout {
				st.mutex.Unlock()
				continue
			}

			dbg(3, "main", "%s: port state %d timeout after %ds",
				st.tag, st.state, (now - st.since)/1e9)
		}

		// authentication needed
		st.state = STATE_NEEDS_AUTH
		st.since = nanotime()
		st.timeout = st.since + 5e9 // give it 5 sec
		st.mutex.Unlock()

		// request authentication
		go S.state_start_auth(st)
	}
}
