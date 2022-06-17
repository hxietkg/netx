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
	"netx/utils"

	"github.com/spf13/cobra"
)

var (
	packetstr    string
)

// rootCmd represents the base command when called without any subcommands
var txCmd = &cobra.Command{
	Use:   "tx",
	Short: "Send packets",
	Long: `
	Send`,
	Run: txHandler,
}

func init() {
	txCmd.Flags().IntVarP(&ifa, "interface", "i", 0, "Interface used for tx")
	txCmd.Flags().StringVarP(&ifname, "ifname", "n", "", "Interface used for tx")
	txCmd.Flags().StringVarP(&packetstr, "packet", "p", "", "Packet string in hex format")
	rootCmd.AddCommand(txCmd)
}

func txHandler(cmd *cobra.Command, args []string) {
	n := len(packetstr)
	if (n % 2) != 0 {
		n--
	}
	minlen := 64
	if n / 2 > minlen {
		minlen = n / 2
	}
	data := make([]byte, minlen)
	for i := 0; i < n; i += 2 {
		s := packetstr[i:i+2]
		var k byte
		fmt.Sscanf(s, "%02x", &k)
		data[i/2] = k
	}

	pkt := utils.NewPacket(minlen, data)

	if len(ifname) > 0 {
		ifa = utils.GetIfIndex(ifname)
	}
	iface := utils.OpenInterface(ifa)
	log.Printf("Open interface %d, %s/%s", ifa, iface.Name, iface.Desc)
	utils.SendPacket(iface, pkt)
	utils.CloseInterface(iface)
}
