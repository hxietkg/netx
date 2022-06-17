/*
Copyright © 2021 Hongsheng Xie
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"log"
	"time"

	//"github.com/google/gopacket"
	//"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type HostInterface struct {
	Handle *pcap.Handle
	Name    string
	Desc    string
}

type Packet struct {
	Length        int
	Data          []byte
	Seconds       uint32
	NanoSeconds   uint32
}

const (
	// The same default as tcpdump.
	DefaultSnapLen = 262144
)

func NewPacket(Length int, Data []byte) *Packet {
	return &Packet{
		Length: Length,
		Data: Data,
		Seconds: 0,
		NanoSeconds: 0,
	}
}

func ListInterfaces() ([]HostInterface) {
	var ret []HostInterface
	ifaces, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	for _, iface := range ifaces {
		ret = append(ret, HostInterface{nil, iface.Name, iface.Description})
	}
	return ret
}

func GetIfIndex(ifname string) int {
	ifaces := ListInterfaces()
	for idx, iface := range ifaces {
		if iface.Name == ifname {
			return idx
		}
	}
	return 0
}

func OpenInterface(ifa int) *HostInterface {
	ifaces := ListInterfaces()
	ifName := ifaces[ifa].Name
	handle, err := pcap.OpenLive(ifName, DefaultSnapLen, true,
				     pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	return &HostInterface{handle, ifName, ifaces[ifa].Desc}
}

func CloseInterface(iface *HostInterface) {
	iface.Handle.Close()
}

func ReadPacket(iface *HostInterface, fromTm *time.Time) *Packet {
	h := iface.Handle
	data, ci, err := h.ReadPacketData()
	if err != nil {
		log.Fatal(err)
	}
	pkt := NewPacket(ci.CaptureLength, data)
	if fromTm != nil {
		tm := time.Since(*fromTm)
		pkt.Seconds = uint32(tm.Seconds())
		pkt.NanoSeconds = uint32(tm.Nanoseconds() % 1000000000)
	}
	return pkt
}

func SendPacket(iface *HostInterface, pkt *Packet) {
	h := iface.Handle
	if err := h.WritePacketData(pkt.Data[0:pkt.Length]); err != nil {
		log.Fatal(err)
	}
}
