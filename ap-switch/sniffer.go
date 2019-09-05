package main

import (
	"net"
	"time"
	"fmt"
	"github.com/google/gopacket/pcap"
)

type SnifferMsg struct {
	iface      string
	mac        net.HardwareAddr
	ip         net.IP
}

func (S *Switch) sniffer(iface string, out chan SnifferMsg) {
	var pkt []byte
	var db map[string]int64
	
	for inerr := 0; true; time.Sleep(time.Second) {
		// reset the database for this interface
		db = make(map[string]int64)

		// try listening to the first 64 bytes (enough for link+ip4/6 headers)
		h, err := pcap.OpenLive(iface, 64, false, pcap.BlockForever)
		if err != nil {
			if inerr != 1 { dbgErr(2, "sniffer", err); inerr = 1; }
			continue
		} else if inerr == 1 {
			inerr = 0
		}

		// check if link type == Ethernet
		if h.LinkType() != 1 {
			die("sniffer", "invalid link type on %s: %d", iface, h.LinkType())
		}

		// only inbound traffic
		err = h.SetDirection(pcap.DirectionIn)
		if err != nil {
			dieErr("sniffer", err)
		}

		// attach a BPF filter: inbound ARP (for IPv4) or NDP Neighbor Solicitation (for IPv6)
		err = h.SetBPFFilter("arp or (icmp6 and ip6[40] == 135)")
		if err != nil {
			dieErr("sniffer", err)
		}

		// read from socket
		for {
			pkt, _, err = h.ZeroCopyReadPacketData()
			if err != nil { break }

			// packet too short?
			if len(pkt) < 34 { continue }

			// get source MAC
			var mac net.HardwareAddr
			off := 6
			mac = append(mac, pkt[off:off+6]...)

			// is 802.1Q or 802.1ad? ignore
			off += 6
			if pkt[off] == 0x81 && pkt[off+1] == 0x00 {
				dbg(5, "sniffer", "%s: MAC %s: ignoring 802.1Q VLAN frame", iface, mac)
				continue // off += 4 // single tag
			} else if pkt[off] == 0x88 && pkt[off+1] == 0xa8 {
				dbg(5, "sniffer", "%s: MAC %s: ignoring 802.1ad VLAN frame", iface, mac)
				continue // off += 8 // double tag
			}

			// read ethertype
			etype := uint16(pkt[off]) << 8 | uint16(pkt[off+1])
			if etype < 1536 { continue } // ignore

			// read the IP address
			var ip net.IP
			switch etype {
			case 0x0806: // ARP
				off += 2 + 14 // arp sender IP
				if len(pkt) < off + 4 { continue }
				ip = append(ip, pkt[off:off+4]...)
			case 0x86DD: // IPv6 -> ICMPv6 -> NDP -> Neighbor Solicitation (note the BPF filter)
				off += 2 + 8 // ipv6 source address
				if len(pkt) < off + 16 { continue }
				ip = append(ip, pkt[off:off+16]...)
			default: continue // ignore
			}

			// invalid IP?
			if !ip.IsGlobalUnicast() {
				dbg(5, "sniffer", "%s: MAC %s: ignoring IP %s", iface, mac, ip)
				continue
			}

			// already in db?
			key := fmt.Sprintf("%s/%s", mac, ip)
			if t, ok := db[key]; ok && t > time.Now().Unix() {
				continue // a duplicate (already seen)
			} else { // set a timeout
				db[key] = time.Now().Unix() + 86400 // 1 day, TODO: random delay
			}

			// print
			out <- SnifferMsg{iface, mac, ip}
		}

		// broke due to error?
		if err != nil {
			if inerr != 2 { dbgErr(2, "sniffer", err); inerr = 2; }
		} else {
			inerr = 0
		}

		// prepare to re-open
		h.Close()
	}
}
