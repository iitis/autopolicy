package main

import (
	"net"
	"os/exec"
)

// TODO: context + timeouts

func tc_cleanup(iface string) {
	cmd := exec.Command("tc", "qdisc", "del",
		"dev", iface, "handle", "ffff:", "ingress")
	cmd.Run() // ignore errors
}

func tc_init(iface string) error {
	cmd := exec.Command("tc", "qdisc", "add",
		"dev", iface, "handle", "ffff:", "ingress")
	if err := cmd.Run(); err != nil {
		return err
	}

	cmd = exec.Command("tc", "filter", "add",
		"dev", iface, "parent", "ffff:", "prio", "2", "protocol", "ip",
		"matchall",
		"action", "drop")
	if err := cmd.Run(); err != nil {
		return err
	}

	return nil
}

func tc_provision(iface string, mac net.HardwareAddr) error {
	cmd := exec.Command("tc", "filter", "add",
		"dev", iface, "parent", "ffff:", "prio", "1", "protocol", "ip",
		"u32", "match", "ether", "src", mac.String(),
		"action", "gact", "ok")
	return cmd.Run()
}
