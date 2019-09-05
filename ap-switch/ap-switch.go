package main

import (
	"flag"
)

type Switch struct {
	opts struct {
		dbg            int
		// --
		ifaces         []string
	}
	
}

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

	sniffer_out := make(chan SnifferMsg, 100)
	for i := range S.opts.ifaces {
		dbg(1, "main", "starting sniffer on %s", S.opts.ifaces[i])
		go S.sniffer(S.opts.ifaces[i], sniffer_out)
	}

	// read from sniffers
	for msg := range sniffer_out {
		dbg(0, "main", "new host on %s: %s = %s", msg.iface, msg.mac, msg.ip)
	}
}
