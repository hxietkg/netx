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
	"log"
	"netx/utils"

	"github.com/spf13/cobra"
)

var (
	arp_srcmac     string
	arp_srcip      string
	arp_targetmac  string
	arp_targetip   string
	opcode         int
)

// rootCmd represents the base command when called without any subcommands
var arpFloodCmd = &cobra.Command{
	Use:   "arpflood",
	Short: "Send packets",
	Long: `
	Send`,
	Run: arpFloodHandler,
}

func init() {
	arpFloodCmd.Flags().IntVarP(&ifa, "interface", "i", 0, "Interface used for tx")
	arpFloodCmd.Flags().StringVarP(&ifname, "ifname", "", "", "Interface used for tx")
	arpFloodCmd.Flags().StringVarP(&srcmac, "src-mac", "", "", "Source mac")
	arpFloodCmd.Flags().StringVarP(&destmac, "dest-mac", "", "", "Dest mac")
	arpFloodCmd.Flags().StringVarP(&arp_srcmac, "arp-src-mac", "", "", "Source mac")
	arpFloodCmd.Flags().StringVarP(&arp_srcip, "arp-src-ip", "", "", "Source ip")
	arpFloodCmd.Flags().StringVarP(&arp_targetmac, "arp-target-mac", "", "", "Dest mac")
	arpFloodCmd.Flags().StringVarP(&arp_targetip, "arp-target-ip", "", "", "Dest ip")
	arpFloodCmd.Flags().IntVarP(&opcode, "arp-op-code", "", 1, "Operation code")
	arpFloodCmd.Flags().IntVarP(&count, "count", "c", 1, "Count of flood")
	rootCmd.AddCommand(arpFloodCmd)
}

func arpFloodHandler(cmd *cobra.Command, args []string) {
	data := make([]byte, 1500)
	n := utils.CreateEthHdr(data, 0, destmac, srcmac, 0x0806)
	n += utils.CreateArpHdr(data, n, arp_srcmac, arp_srcip, arp_targetmac, arp_targetip, opcode)
	if n < 64 {
		n = 64
	}
	pkt := utils.NewPacket(n, data)

	if len(ifname) > 0 {
		ifa = utils.GetIfIndex(ifname)
	}
	iface := utils.OpenInterface(ifa)
	log.Printf("Open interface %d, %s/%s", ifa, iface.Name, iface.Desc)
	for i := 0; i < count; i++ {
		utils.SendPacket(iface, pkt)
	}
	utils.CloseInterface(iface)
}
