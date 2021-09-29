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
	"fmt"
)

func GetMacAddr(data []byte, offset int) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
			           data[offset+0], data[offset+1],
			           data[offset+2], data[offset+3],
			           data[offset+4], data[offset+5])
}

func GetVlans(data []byte, offset int) (int, string) {
	str := ""
	off := offset
	for {
		tag := GetInt16Val(data, off)
		if tag != 0x8200 {
			break
		}
		off += 2
		str += fmt.Sprintf("%d ", GetInt16Val(data, off) & 0x0fff)
		off += 2
	}
	return off - offset, str
}

func GetEthHdr(data []byte, offset int) (int, string) {
	str := fmt.Sprintf("  ==> ETH: srcmac: %s, destmac: %s",
	                   GetMacAddr(data, offset + 6),
					   GetMacAddr(data, offset + 0))
	n, vlanstr := GetVlans(data, offset + 12)
	if n > 0 {
		str += fmt.Sprintf(", vlans: %s", vlanstr)
	}
	n += 12
	str += fmt.Sprintf(", ethtype:0x%04x",
	                   GetInt16Val(data, offset + n))
	n += 2
	return n, str
}

func GetIpv4Addr(data []byte, offset int) string {
	return fmt.Sprintf("%d:%d:%d:%d",
			           data[offset+0], data[offset+1],
			           data[offset+2], data[offset+3])
}

func GetIpv6Addr(data []byte, offset int) string {
	return fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
			           data[offset+0], data[offset+1],
			           data[offset+2], data[offset+3],
			           data[offset+4], data[offset+5],
			           data[offset+6], data[offset+7],
			           data[offset+8], data[offset+9],
			           data[offset+10], data[offset+11],
			           data[offset+12], data[offset+13],
			           data[offset+14], data[offset+15])
}

func GetIpv4Hdr(data []byte, offset int) (int, string) {
	str := fmt.Sprintf("  ==> IPv4: srcip: %s, destip: %s, proto: %d",
	                   GetIpv4Addr(data, offset + 12),
					   GetIpv4Addr(data, offset + 16),
					   GetInt8Val(data, offset + 9))
	hdrlen := (data[offset] & 0x0f) * 4
	return int(hdrlen), str
}

func GetIpv6Hdr(data []byte, offset int) (int, string) {
	str := fmt.Sprintf("  ==> IPv6: srcip: %s, destip: %s, proto: %d",
	                   GetIpv6Addr(data, offset + 8),
					   GetIpv6Addr(data, offset + 24),
					   GetInt8Val(data, offset + 6))
	return 40, str
}

func GetArpHdr(data []byte, offset int) (int, string) {
	str := fmt.Sprintf("  ==> ARP: hwType: 0x%04x, proto: 0x%04x, hwSize: %d, protoSize: %d, opCode: %d, srcMac: %s, srcIp: %s, targetMac: %s, targetIp: %s",
	                   GetInt16Val(data, offset),
					   GetInt16Val(data, offset + 2),
					   GetInt8Val(data, offset + 4),
					   GetInt8Val(data, offset + 5),
					   GetInt16Val(data, offset + 6),
					   GetMacAddr(data, offset + 8),
					   GetIpv4Addr(data, offset + 14),
					   GetMacAddr(data, offset + 18),
					   GetIpv4Addr(data, offset + 24))
	return 28, str
}

func GetUdpHdr(data []byte, offset int) (int, string) {
	str := fmt.Sprintf("  ==> UDP: srcport: %d, destport: %d",
					   GetInt16Val(data, offset + 0),
					   GetInt16Val(data, offset + 2))
	return 8, str
}

func GetTcpHdr(data []byte, offset int) (int, string) {
	str := fmt.Sprintf("  ==> TCP: srcport: %d, destport: %d",
					   GetInt16Val(data, offset + 0),
					   GetInt16Val(data, offset + 2))
	return 20, str
}

func GetIcmpHdr(data []byte, offset int) (int, string) {
	str := fmt.Sprintf("  ==> ICMP: type: %d, code: %d",
					   GetInt8Val(data, offset + 0),
					   GetInt8Val(data, offset + 1))
	return 8, str
}

func GeneratePktStr(data []byte) string {
	offset := 0
	str := ""
	n, s := GetEthHdr(data, offset)
	str += s
	offset += n
	ethType := GetInt16Val(data, offset - 2)
	str += "\n"
	proto := uint(0)
	if ethType == 0x0800 {
		n, s = GetIpv4Hdr(data, offset)
		proto = GetInt8Val(data, offset + 9)
		str += s
		offset += n
	} else if ethType == 0x86dd {
		n, s = GetIpv6Hdr(data, offset)
		proto = GetInt8Val(data, offset + 6)
		str += s
		offset += n
	} else if ethType == 0x0806 {
		n, s = GetArpHdr(data, offset)
		str += s
		offset += n
	}
	if proto > 0 {
		if proto == 1 {
			n, s = GetIcmpHdr(data, offset)
		} else if proto == 6 {
			n, s = GetTcpHdr(data, offset)
		} else if proto == 17 {
			n, s = GetUdpHdr(data, offset)
		} else {
			n = 0
			s = ""
		}
		str += "\n"
		str += s
		offset += n
	}
	return str
}

func PutInt16Val(data []byte, offset int, val uint) {
	data[offset+0] = byte((val >> 8) & 0xff)
	data[offset+1] = byte(val & 0xff)
}

func PutInt32Val(data []byte, offset int, val uint) {
	PutInt16Val(data, offset, (val >> 16) & 0xffff)
	PutInt16Val(data, offset + 2, val & 0xffff)
}

func PutInt64Val(data []byte, offset int, val uint) {
	PutInt32Val(data, offset, (val >> 32) & 0xffffffff)
	PutInt32Val(data, offset + 4, val & 0xffff)
}

func CheckSum(data []byte) uint16 {
	var (
		sum    uint32
		length int = len(data)
		index  int
	)
	for length > 1 {
		sum += uint32(data[index]) << 8 + uint32(data[index+1])
		index += 2
		length -= 2
	}
	if length > 0 {
		sum += uint32(data[index])
	}
	sum += (sum >> 16)

	return uint16(^sum)
}

func PesudoChecksum(iph []byte, tseglen int, data []byte) uint16 {
	length := len(data)
	d := make([]byte, length + 12)
	for i := 0; i < 8; i++ {
		d[i] = iph[12+i]
	}
	d[8] = byte(0x00)
	d[9] = iph[9]
	PutInt16Val(d, 10, uint(tseglen))
	copy(d[12:], data[:])
	return CheckSum(d)
}

func CreateMacAddr(data []byte, offset int, mac string) {
	var m1, m2, m3, m4, m5, m6 byte
	fmt.Sscanf(mac, "%02x:%02x:%02x:%02x:%02x:%02x",
	           &m1, &m2, &m3, &m4, &m5, &m6)
	data[offset+0] = m1
	data[offset+1] = m2
	data[offset+2] = m3
	data[offset+3] = m4
	data[offset+4] = m5
	data[offset+5] = m6
}

func CreateIpv4Addr(data []byte, offset int, ipv4 string) {
	var m1, m2, m3, m4 byte
	fmt.Sscanf(ipv4, "%d.%d.%d.%d",
	           &m1, &m2, &m3, &m4)
	data[offset+0] = m1
	data[offset+1] = m2
	data[offset+2] = m3
	data[offset+3] = m4
}

func CreateEthHdr(data []byte, offset int, destmac, srcmac string, etype int) int {
	off := offset
	CreateMacAddr(data, off, destmac)
	off += 6
	CreateMacAddr(data, off, srcmac)
	off += 6
	PutInt16Val(data, off, uint(etype))
	off += 2
	return off - offset
}

func CreateArpHdr(data []byte, offset int, srcmac, srcip, targetmac, targetip string, opcode int) int {
	off := offset
	PutInt16Val(data, off, 1)
	off += 2
	PutInt16Val(data, off, 0x0800)
	off += 2
	data[off] = byte(6)
	off++
	data[off] = byte(4)
	off++
	PutInt16Val(data, off, uint(opcode))
	off += 2
	CreateMacAddr(data, off, srcmac)
	off += 6
	CreateIpv4Addr(data, off, srcip)
	off += 4
	CreateMacAddr(data, off, targetmac)
	off += 6
	CreateIpv4Addr(data, off, targetip)
	off += 4
	return off - offset
}

func CreateIpv4Hdr(data []byte, offset int, srcip, destip string, proto int) int {
	off := offset
	data[off] = byte(0x45)
	off++
	data[off] = byte(0x00)
	off++
	PutInt16Val(data, off, 0) //Total length
	off += 2
	PutInt16Val(data, off, 0xabcd) //ID
	off += 2
	data[off] = byte(0x40) //Don't frag
	off++
	data[off] = byte(0x00) //Fragment
	off++
	data[off] = byte(0x80) //TTL
	off++
	data[off] = byte(proto) //Proto
	off++
	PutInt16Val(data, off, 0) //Checksum
	off += 2
	CreateIpv4Addr(data, off, srcip)
	off += 4
	CreateIpv4Addr(data, off, destip)
	off += 4
	return off - offset
}

func CreateIcmpHdr(data []byte, offset int, icmptype int, icmpcode int) int {
	off := offset
	data[off] = byte(icmptype)
	off++
	data[off] = byte(icmpcode)
	off++
	PutInt16Val(data, off, 0) //Checksum
	off += 2
	PutInt16Val(data, off, 0x1235)
	off += 2
	PutInt16Val(data, off, 0x5678)
	off += 2
	return off - offset
}

func CreateTcpHdr(data[] byte, offset int, srcport, dstport int) int {
	off := offset
	PutInt16Val(data, off, uint(srcport))
	off += 2
	PutInt16Val(data, off, uint(dstport))
	off += 2
	PutInt32Val(data, off, 0x12345678) //seq
	off += 4
	PutInt32Val(data, off, 0x87654321) //ack
	off += 4
	PutInt16Val(data, off, 0x5002) //20 bytes header, SYN
	off += 2
	PutInt16Val(data, off, 0x6000) //window
	off += 2
	PutInt16Val(data, off, 0) //Checksum
	off += 2
	PutInt16Val(data, off, 0) //UG pointer
	off += 2
	return off - offset
}