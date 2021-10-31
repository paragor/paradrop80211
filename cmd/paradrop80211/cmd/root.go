package cmd

import (
	"github.com/spf13/cobra"
)

const (
	FlagListenIface = "listen-iface"
	FlagAttackIface = "attack-iface"
)

var rootCmd = &cobra.Command{
	Use:   "paradrop80211",
}

func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	rootCmd.PersistentFlags().StringP("listen-iface", "a", "wlp3s0mon", "interface in promisc mode to listen")
	rootCmd.PersistentFlags().StringP("attack-iface", "l", "wlp3s0mon", "interface in promisc mode to attack")
}
