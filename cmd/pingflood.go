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

// rootCmd represents the base command when called without any subcommands
var pingFloodCmd = &cobra.Command{
	Use:   "pingflood",
	Short: "Send ping packets",
	Long: `
	Send`,
	Run: pingFloodHandler,
}

func init() {
	pingFloodCmd.Flags().IntVarP(&ifa, "interface", "i", 0, "Interface used for tx")
	pingFloodCmd.Flags().StringVarP(&ifname, "ifname", "", "", "Interface used for tx")
	pingFloodCmd.Flags().StringVarP(&srcmac, "src-mac", "", "", "Source mac")
	pingFloodCmd.Flags().StringVarP(&destmac, "dest-mac", "", "", "Dest mac")
	pingFloodCmd.Flags().StringVarP(&srcip, "src-ip", "", "", "Source ip")
	pingFloodCmd.Flags().StringVarP(&destip, "dest-ip", "", "", "Dest ip")
	pingFloodCmd.Flags().IntVarP(&count, "count", "c", 1, "Count of flood")
	rootCmd.AddCommand(pingFloodCmd)
}

func pingFloodHandler(cmd *cobra.Command, args []string) {
	data := make([]byte, 1500)
	n1 := utils.CreateEthHdr(data, 0, destmac, srcmac, 0x0800)
	n2 := utils.CreateIpv4Hdr(data, n1, srcip, destip, 0x01)
	n3 := utils.CreateIcmpHdr(data, n1 + n2, 0x08, 0x00)
	n4 := 500 //payload, random
	tlen := n1 + n2 + n3 + n4

	utils.PutInt16Val(data, n1 + 2, uint(tlen - n1))
	cksum := utils.CheckSum(data[n1:n1+n2])
	utils.PutInt16Val(data, n1 + 10, uint(cksum))

	cksum = utils.CheckSum(data[n1+n2:tlen])
	utils.PutInt16Val(data, n1 + n2 + 2, uint(cksum))

	pkt := utils.Packet{tlen, data}

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
