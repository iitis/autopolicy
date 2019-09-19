package main

import (
	"fmt"
	"strings"
	"context"
	"net"
	"os/exec"
)

const (
	TC_TIMEOUT = 1e9
)

var (
	tc_path = "tc"
)

func init() {
	var err error
	tc_path, err = exec.LookPath("tc")
	if err != nil {
		die("tc", "tc binary not found in $PATH: %s", err)
	}
}

func (S *Switch) tc_run(args ...string) error {
	ctx, cancel := context.WithTimeout(S.ctx, TC_TIMEOUT)
	defer cancel()

	// prepare the command
	cmd := exec.CommandContext(ctx, tc_path, args...)

	// store stderr
	var buf strings.Builder
	cmd.Stderr = &buf

	// run it and wait till end
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %s", err, strings.TrimSpace(buf.String()))
	}

	return nil
}

func (S *Switch) tc_run_io(stdin string, args ...string) (stdout string, stderr string, err error) {
	ctx, cancel := context.WithTimeout(S.ctx, TC_TIMEOUT)
	defer cancel()

	// prepare the command
	cmd := exec.CommandContext(ctx, tc_path, args...)

	// need to write stdin?
	if len(stdin) > 0 { cmd.Stdin = strings.NewReader(stdin) }

	// read stdout and stderr
	var bout, berr strings.Builder
	cmd.Stdout = &bout
	cmd.Stderr = &berr

	// run it and wait till end
	err = cmd.Run()

	return bout.String(), berr.String(), err
}

func (S *Switch) tc_cleanup(iface string) error {
	return S.tc_run("qdisc", "del", "dev", iface, "handle", "ffff:", "ingress")
}

func (S *Switch) tc_init(iface string) error {
	err := S.tc_run("qdisc", "add", "dev", iface, "handle", "ffff:", "ingress")
	if err != nil { return err }

	// FIXME: allow for identity fetching

	return S.tc_run("filter", "add", "dev", iface, "parent", "ffff:",
		"prio", "2", "protocol", "ip",
		"matchall",
		"action", "drop")
}

func (S *Switch) tc_provision(iface string, mac net.HardwareAddr) error {
	return S.tc_run("filter", "add", "dev", iface, "parent", "ffff:",
		"prio", "1", "protocol", "ip",
		"u32", "match", "ether", "src", mac.String(),
		"action", "gact", "ok")
}
