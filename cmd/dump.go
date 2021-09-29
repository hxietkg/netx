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
	dump_listif bool
)

// rootCmd represents the base command when called without any subcommands
var dumpCmd = &cobra.Command{
	Use:   "dump",
	Short: "Dump packets",
	Long: `
	dump`,
	Run: dumpHandler,
}

func init() {
	dumpCmd.Flags().BoolVarP(&dump_listif, "list-interfaces", "l", false, "List all interfaces in the host")
	dumpCmd.Flags().IntVarP(&ifa, "interface", "i", 0, "Interface to be dumped")
	dumpCmd.Flags().StringVarP(&ifname, "ifname", "", "", "Interface to be dumped")
	dumpCmd.Flags().IntVarP(&count, "count", "c", 1, "Count of flood")
	rootCmd.AddCommand(dumpCmd)
}

func dumpPacket(pkt utils.Packet, idx int) {
	str := utils.GeneratePktStr(pkt.Data)
	log.Printf(" packet : ============[%d]\n%s", idx, str)
}

func dumpInterface() {
	if len(ifname) > 0 {
		ifa = utils.GetIfIndex(ifname)
	}
	iface := utils.OpenInterface(ifa)
	log.Printf("Open interface %d, %s/%s", ifa, iface.Name, iface.Desc)
	for i := 0; i < count; i++ {
		pkt := utils.ReadPacket(iface)
		dumpPacket(pkt, i)
	}
	utils.CloseInterface(iface)
}

func dumpHandler(cmd *cobra.Command, args []string) {
	if dump_listif {
		ifaces := utils.ListInterfaces()
		for idx, iface := range ifaces {
			log.Printf("iface [%d] -- %s/%s", idx, iface.Name, iface.Desc)
			idx++
		}
		return
	}
	dumpInterface()
}
