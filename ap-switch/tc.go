package main

import (
	"strconv"
	"fmt"
	"strings"
	"context"
	"net"
	"os/exec"
)

const (
	TC_TIMEOUT = 1e9
)

const (
	_ = iota
	PREF_INITv4
	PREF_INITv6
	PREF_DEVICE
	PREF_LASTv4
	PREF_LASTv6
)

var (
	tc_path = "tc"
)

func init() {
	var err error
	tc_path, err = exec.LookPath("tc")
	if err != nil { die("tc", "tc binary not found in $PATH: %s", err) }
}

func (S *Switch) tc_run(prefix []string, pref int, args ...string) (int, error) {
	stderr, err := S.tc_run_io(nil, nil, prefix, pref, args...)

	// ignore "File exists" errors
	if err != nil {		
		stderr = strings.TrimSpace(stderr)
		if !strings.HasPrefix(stderr, "RTNETLINK answers: File exists") {
			return -1, fmt.Errorf("%s: %s %s", err, stderr, args)
		}
	}

	return pref+1, nil
}

func (S *Switch) tc_run_io(stdin *string, stdout *string, prefix []string, pref int, args ...string) (stderr string, err error) {
	ctx, cancel := context.WithTimeout(S.ctx, TC_TIMEOUT)
	defer cancel()

	// produce the command line
	if pref > 0 { prefix = append(prefix, "pref", fmt.Sprintf("%d", pref)) }
	if len(prefix) > 0 { args = append(prefix, args...) }

	// prepare the command
	cmd := exec.CommandContext(ctx, tc_path, args...)
	dbg(5, "tc", "tc_run_io: %s", cmd)

	// need to write stdin?
	if stdin != nil { cmd.Stdin = strings.NewReader(*stdin) }

	// read stdout and stderr
	var bout, berr strings.Builder
	if stdout != nil { cmd.Stdout = &bout }
	cmd.Stderr = &berr

	// run it and wait till end
	err = cmd.Run()

	// return
	if stdout != nil { *stdout = bout.String() }
	return berr.String(), err
}

func (S *Switch) tc_cleanup(iface string) error {
	_, err1 := S.tc_run(nil, 0, "qdisc", "del", "dev", iface, "root")
	_, err2 := S.tc_run(nil, 0, "qdisc", "del", "dev", iface, "handle", "ffff:", "ingress")
	if err1 != nil { return err1 } else { return err2 }
}

func (S *Switch) tc_init(iface string) error {
	// add prio queue
	_, err := S.tc_run(nil, 0, "qdisc", "add", "dev", iface, "handle", "1:", "root", "prio")
	if err != nil { return err }

	// add ingress queue
	_, err = S.tc_run(nil, 0, "qdisc", "add", "dev", iface, "handle", "ffff:", "ingress")
	if err != nil { return err }

	// collect all my IP addresses
	addrs, err := net.InterfaceAddrs()
	if err != nil { return err }

	// allow for IP communication with this host
	prefix := []string{ "filter", "add", "dev", iface, "parent", "ffff:", "protocol", "" }
	proto := len(prefix) - 1
	for i := range addrs {
		// check if IP is OK
		addr, ok := addrs[i].(*net.IPNet)
		if !ok || !addr.IP.IsGlobalUnicast() { continue }

		// execute
		if addr.IP.To4() != nil {
			prefix[proto] = "ip"
			_, err = S.tc_run(prefix, PREF_INITv4,
				"flower", "dst_ip", addr.IP.String(), "action", "gact", "ok")
		} else {
			prefix[proto] = "ipv6"
			_, err = S.tc_run(prefix, PREF_INITv6,
				"flower", "dst_ip", addr.IP.String(), "action", "gact", "ok")
		}

		if err != nil { return err }
	}

	// drop the rest of IPv4
	prefix[proto] = "ip"
	_, err = S.tc_run(prefix, PREF_LASTv4, "matchall", "action", "drop")
	if err != nil { return err }

	// drop the rest of IPv6
	prefix[proto] = "ipv6"
	_, err = S.tc_run(prefix, PREF_LASTv6, "matchall", "action", "drop")
	if err != nil { return err }

	// ok!
	return nil
}

func (S *Switch) tc_deprovision(st *State, err error) error {
	prefix := []string{ "filter", "del", "dev", st.iface, "parent", "ffff:" }
	S.tc_run(prefix, PREF_DEVICE, "protocol", "ip", "flower", "src_mac", st.mac.String())
	S.tc_run(prefix, 0, "chain", st.tc_chain)

	prefix2 := []string{ "filter", "del", "dev", st.iface, "parent", "1:" }
	S.tc_run(prefix2, PREF_DEVICE, "protocol", "ip", "flower", "dst_mac", st.mac.String())
	S.tc_run(prefix2, 0, "chain", st.tc_chain)

	return err
}

func (S *Switch) tc_provision(st *State, profile map[string]interface{}) (err error) {
	// deprovision first
	S.tc_deprovision(st, nil)
	
	// from device
	from, ok := profile["from_device"].(map[string]interface{})
	if ok {
		prefix := []string{ "filter", "replace", "dev", st.iface,
		"parent", "ffff:", "protocol", "ip", "chain", st.tc_chain }

		err = S.tc_provision_exec(prefix, from)
		if err != nil { return err }

		_, err = S.tc_run(prefix[:len(prefix)-2], PREF_DEVICE,
		"flower", "src_mac", st.mac.String(),
		"action", "goto", "chain", st.tc_chain)
		if err != nil { return S.tc_deprovision(st, err) }
	}

	// to_device
	to, ok := profile["to_device"].(map[string]interface{})
	if ok {
		prefix2 := []string{ "filter", "replace", "dev", st.iface,
		"parent", "1:", "protocol", "ip", "chain", st.tc_chain }

		err = S.tc_provision_exec(prefix2, to)
		if err != nil { return err }

		_, err = S.tc_run(prefix2[:len(prefix2)-2], PREF_DEVICE,
		"flower", "dst_mac", st.mac.String(),
		"action", "goto", "chain", st.tc_chain)
		if err != nil { return S.tc_deprovision(st, err) }
	}

	return nil
}

func (S *Switch) tc_provision_exec(prefix []string, rules map[string]interface{}) error {
	var err error
	pref := 1

	// bit-rate
	vi, ok := rules["rate"]
	if ok {
		var rate float64
		switch v := vi.(type) {
		case float64: rate = v
		case int:     rate = float64(v)
		case string:  rate, _ = strconv.ParseFloat(v, 64)
		}
		if rate <= 0 || rate != rate { return E("invalid rate: %v (%T)", rate, rate) }

		pref, err = S.tc_run(prefix, pref, "matchall", "action", "police",
			"rate",  fmt.Sprintf("%.3fmbit", 1.025*rate),
			"burst", fmt.Sprintf("%.3fmbit", 3*rate),
			"conform-exceed", "drop/continue")
		if err != nil { return err }
	}

	// FIXME:
	// - connections: block anything above the limit (remember about non-TCP/UDP)
	// - src_ips: block many source IP addresses
	// - resolvers: block non-listed DNS resolvers

	// what gact action if nothing below matches?
	policy := "ok"

	// blocked destinations
	vi, ok = rules["block"]
	if ok {
		svc, err := tc_services_parse(vi)
		if err != nil { return err }

		pref, err = S.tc_services_policy(svc, prefix, pref, "drop")
		if err != nil { return err }
	}

	// allowed destinations
	vi, ok = rules["allow"]
	if ok {
		policy = "drop" // block everything that won't match here

		svc, err := tc_services_parse(vi)
		if err != nil { return err }

		pref, err = S.tc_services_policy(svc, prefix, pref, "ok")
		if err != nil { return err }
	}		

	// finally: set policy
	pref, err = S.tc_run(prefix, pref, "matchall", "action", policy)
	if err != nil { return err }

	return nil
}

func (S *Switch) tc_services_policy(services []tc_service, prefix []string, pref int, gact string) (
	newpref int, err error) {
	for _, tb := range services {
		r := []string{ "flower" }

		if len(tb.prefix) > 0 {
			r = append(r, tb.dir + "_ip", tb.prefix)
		}

		if len(tb.tp) > 0 {
			r = append(r, "ip_proto", tb.tp)
		}

		if len(tb.ports) == 0 {
			pref, err = S.tc_run(prefix, pref, append(r, "action", gact)...)
			if err != nil { return -1, err }
		} else {
			for _, p := range tb.ports {
				pref, err = S.tc_run(prefix, pref, append(r, tb.dir + "_port", p, "action", gact)...)
				if err != nil { return -1, err }
			}
		}
	}

	return pref, nil
}

type tc_service struct {
	dir     string     // "" or src or dst
	prefix  string     // or *
	tp      string     // tcp or udp
	ports   []string   // port list
}
func tc_services_parse(bi interface{}) (ret []tc_service, err error) {
	specs := []string{}

	switch v := bi.(type) {
	case nil: // empty?
		break
	case string:
		specs = append(specs, v)
	case []interface{}:
		for _, vi := range v {
			switch v2 := vi.(type) {
			case string:
				specs = append(specs, v2)
			default:
				return nil, fmt.Errorf("invalid element: %v (%T)", v2, v2)
			}
		}
	default:
		return nil, fmt.Errorf("invalid value: %v (%T)", v, v)
	}

	for _, b := range specs {
		var tcb tc_service
		var ports string

		d := strings.Split(b, " ")
		switch len(d) {
		case 1: tcb.tp = d[0]
		case 4: ports = d[3]; fallthrough
		case 3: tcb.tp = d[2]; fallthrough
		case 2: tcb.prefix = d[1]; tcb.dir = d[0]
		default: return nil, fmt.Errorf("invalid number of tokens in %s", b)	
		}

		// direction
		switch tcb.dir {
		case "", "src", "dst": break
		default: return nil, fmt.Errorf("invalid direction '%s' in %s", tcb.dir, b)
		}

		// IP prefix
		switch {
		case len(tcb.prefix) <= 1:
			tcb.prefix = "" // "*"
		default: // verify it's a proper IP address or prefix
			if strings.IndexByte(tcb.prefix, '/') > 0 {
				if _, _, err = net.ParseCIDR(tcb.prefix); err != nil {
					return nil, fmt.Errorf("invalid IP prefix '%s' in %s: %s", tcb.prefix, b, err)
				}
			} else {
				if v := net.ParseIP(tcb.prefix); v == nil {
					return nil, fmt.Errorf("invalid IP address '%s' in %s", tcb.prefix, b)
				}
			}
		}

		// transport protocol
		switch tcb.tp {
		case "","tcp","udp","sctp","icmp","icmpv6": break // take it
		default: // verify if it's a proper unsigned 8-bit number
			_, err = strconv.ParseUint(tcb.tp, 0, 8)
			if err != nil { return nil, fmt.Errorf("invalid protocol '%s' in %s", tcb.tp, b) }
		}

		// ports
		if len(ports) > 0 {
			for _, p := range strings.Split(ports, ",") {
				// trim left/right
				p = strings.TrimSpace(p)
				if len(p) == 0 { continue }

				// validate
				if i := strings.IndexByte(p, '-'); i > 0 && i < len(p)-1 {
					_, err = strconv.ParseUint(p[0:i], 0, 16)
					if err == nil { _, err = strconv.ParseUint(p[i+1:], 0, 16) }
				} else {
					_, err = strconv.ParseUint(p, 0, 16)	
				}

				// take it?
				if err == nil {
					tcb.ports = append(tcb.ports, p)
				} else {
					return nil, fmt.Errorf("invalid port '%s' in %s: %s", p, b, err)
				}
			}
		}

		ret = append(ret, tcb)
	}

	return
}
