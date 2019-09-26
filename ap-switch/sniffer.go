package main

import (
	"net"
	"time"
	"fmt"
	"github.com/google/gopacket/pcapgo" // slow but portable
	"golang.org/x/net/bpf"
)

type SnifferMsg struct {
	iface      string
	mac        net.HardwareAddr
	ip         net.IP
}

func (S *Switch) sniffer(iface string) {
	for inerr := 0; true; time.Sleep(time.Second) {
		// try listening to the first 64 bytes (enough for link+ip4/6 headers)
		h, err := pcapgo.NewEthernetHandle(iface)
		if err != nil {
			if inerr != 1 { dbgErr(2, "sniffer", err); inerr = 1; }
			continue
		} else if inerr == 1 {
			inerr = 0
		}

		// set capture length
		err = h.SetCaptureLength(64)
		if err != nil {
			dieErr("sniffer", err)
		}

		// attach a BPF filter: inbound ARP (for IPv4) or NDP Neighbor Solicitation (for IPv6)
		// tcpdump -s 64 -dd "inbound and (arp or (icmp6 and ip6[40] == 135))"
		err = h.SetBPF([]bpf.RawInstruction{
			{ 0x28, 0, 0, 0xfffff004 },
			{ 0x15, 11, 0, 0x00000004 },
			{ 0x28, 0, 0, 0x0000000c },
			{ 0x15, 8, 0, 0x00000806 },
			{ 0x15, 0, 8, 0x000086dd },
			{ 0x30, 0, 0, 0x00000014 },
			{ 0x15, 3, 0, 0x0000003a },
			{ 0x15, 0, 5, 0x0000002c },
			{ 0x30, 0, 0, 0x00000036 },
			{ 0x15, 0, 3, 0x0000003a },
			{ 0x30, 0, 0, 0x00000036 },
			{ 0x15, 0, 1, 0x00000087 },
			{ 0x6, 0, 0, 0x00000040 },
			{ 0x6, 0, 0, 0x00000000 },
		})
		if err != nil {
			dieErr("sniffer", err)
		}

		// reset the database for this interface
		db := make(map[string]int64)

		// read from socket
		for {
			pkt, ci, err := h.ZeroCopyReadPacketData()
			if err != nil {
				if inerr != 2 { dbgErr(2, "sniffer", err); inerr = 2; }
				break
			} else if inerr == 2 {
				inerr = 0
			}

			// packet too short?
			if len(pkt) < 34 { continue }

			// get source MAC
			var mac net.HardwareAddr
			off := 6
			mac = append(mac, pkt[off:off+6]...)

			// is source MAC broadcast?
			if IsMACBroadcast(mac) { continue }

			// is VLAN? ignore
			if len(ci.AncillaryData) > 0 {
				if vlan, ok := ci.AncillaryData[0].(int); ok {
					dbg(5, "sniffer", "%s: MAC %s: ignoring VLAN %d frame", iface, mac, vlan)
					continue
				}
			}

			// read ethertype
			off += 6
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
			switch {
			case len(ip) == 16 && ip[0] & 0b11100000 != 0x20:
				dbg(5, "sniffer", "%s: MAC %s: IPv6 %s outside of 2000::/3", iface, mac, ip)
				continue
			case !ip.IsGlobalUnicast():
				dbg(5, "sniffer", "%s: MAC %s: ignoring IP %s", iface, mac, ip)
				continue
			}

			// invalid MAC? this really shouldn't happen with a global unicast source address, right?
			if len(ip) == 4 {
				if IsMACMulticastIPv4(mac) { continue }
			} else {
				if IsMACMulticastIPv6(mac) { continue }
			}

			// already in db?
			key := fmt.Sprintf("%s/%s", mac, ip)
			if t, ok := db[key]; ok && t > nanotime() {
				continue // a duplicate (already seen)
			} else { // set a timeout
				// need random eviction?
				if len(db) >= 1e6 {
					for key2 := range db {
						delete(db, key2)
						break
					}
				}
				db[key] = nanotime() + 60e9 // 1 min timeout
			}

			// new MAC-IP seen
			S.snifferq <- SnifferMsg{iface, mac, ip}
		}

		// prepare to re-open
		h.Close()
	}
}

// from https://github.com/newtools/zsocket/blob/master/nettypes/ethframe.go
func IsMACBroadcast(addr net.HardwareAddr) bool {
	return addr[0] == 0xFF && addr[1] == 0xFF && addr[2] == 0xFF &&
	       addr[3] == 0xFF && addr[4] == 0xFF && addr[5] == 0xFF
}

func IsMACMulticastIPv4(addr net.HardwareAddr) bool {
	return addr[0] == 0x01 && addr[1] == 0x00 && addr[2] == 0x5E
}

func IsMACMulticastIPv6(addr net.HardwareAddr) bool {
	return addr[0] == 0x33 && addr[1] == 0x33
}
