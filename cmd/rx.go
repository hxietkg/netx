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

package cmd

import (
	"fmt"
	"log"
	"time"
	"os"
	"os/signal"
	"syscall"
	"encoding/binary"

	"github.com/spf13/cobra"

	"netx/utils"
)

var (
	filename    string
	running	    bool
)

type pcap_header struct {
        magic_number  uint32
        major_version uint16
        minor_version uint16
        reserved1     uint32
        reserved2     uint32
        snap_len      uint32
        link_type     uint32
}

type pkt_header struct {
        sec        uint32
        nsec       uint32
        cap_len    uint32
        ori_len    uint32
}

// rootCmd represents the base command when called without any subcommands
var rxCmd = &cobra.Command{
	Use:   "rx",
	Short: "Receive packets",
	Long: `
	Receive`,
	Run: rxHandler,
}

func ctrl_c_Handler() {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\r- Ctrl+C pressed in Terminal")
		running = false
		os.Exit(0)
	}()
}

func init() {
	rxCmd.Flags().IntVarP(&ifa, "interface", "i", 0, "Interface used for rx")
	rxCmd.Flags().StringVarP(&ifname, "ifname", "n", "", "Interface used for rx")
	rxCmd.Flags().StringVarP(&filename, "file", "f", "", ".pcap file to save packets")
	rootCmd.AddCommand(rxCmd)
}

func SavePacket(pkt *utils.Packet, f *os.File) {
	if f != nil {
		ph := &pkt_header{
			sec:      uint32(pkt.Seconds),
			nsec:     uint32(pkt.NanoSeconds),
			cap_len:  uint32(pkt.Length),
			ori_len:  uint32(pkt.Length),
		}
		binary.Write(f, binary.LittleEndian, ph)
		f.Write(pkt.Data)
		log.Printf(" Received packet len=%d, nsec=%x/%x\n", pkt.Length, pkt.Seconds, pkt.NanoSeconds)
	} else {
		str := utils.GeneratePktStr(pkt.Data)
		log.Printf(" Received packet : ============\n%s", str)
	}
}

func rxHandler(cmd *cobra.Command, args []string) {
	ctrl_c_Handler()
	var fp *os.File
	fp = nil
	if filename != "" {
		f, err := os.Create(filename)
		if err != nil {
			log.Printf("Failed to open file %s", filename)
			return
		}
		fp = f
		defer fp.Close()
		ph := &pcap_header{
			magic_number:    0xa1b23c4d, //0xa1b2c3d4 micro-sec
			major_version:   2,
			minor_version:   4,
			reserved1:       0,
			reserved2:       0,
			snap_len:        utils.DefaultSnapLen,
			link_type:       1,
		}
		binary.Write(fp, binary.LittleEndian, ph)
	}
	if len(ifname) > 0 {
		ifa = utils.GetIfIndex(ifname)
	}
	iface := utils.OpenInterface(ifa)
	defer utils.CloseInterface(iface)
	log.Printf("Open interface %d, %s/%s", ifa, iface.Name, iface.Desc)
	running = true
	StartTime := time.Now()
	for running {
		pkt := utils.ReadPacket(iface, &StartTime)
		SavePacket(pkt, fp)
	}
}

