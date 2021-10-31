package cmd

import (
	"context"
	"github.com/google/gopacket/pcap"
	"github.com/paragor/paradrop80211/pkg/discovering"
	"github.com/paragor/paradrop80211/pkg/logger"
	"github.com/paragor/paradrop80211/pkg/manuf"
	"github.com/paragor/paradrop80211/pkg/wifi"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

const (
	FlagListenCmdUseHopper = "use-hopper"
)

var listenCmd = &cobra.Command{
	Use: "listen",
	RunE: func(cmd *cobra.Command, args []string) error {
		var apCache sync.Map
		var pairsCache sync.Map

		iface, err := cmd.Flags().GetString(FlagListenIface)
		if err != nil {
			return err
		}
		useHoper, err := cmd.Flags().GetBool(FlagListenCmdUseHopper)
		if err != nil {
			return err
		}

		handle, err := pcap.OpenLive(iface, 65536, true, 500*time.Millisecond)
		if err != nil {
			panic(err)
		}
		defer handle.Close()

		pairs := make(chan discovering.PairInfo, 1)
		aps := make(chan discovering.AccessPointInfo, 1)
		ctx, cancel := context.WithCancel(context.Background())

		log := logger.FromContext(ctx)
		defer func() {
			cancel()
			time.Sleep(time.Second)
		}()

		sniffer := wifi.NewSniffer(
			handle,
			[]wifi.PacketProcessor{
				discovering.NewAccessPointDiscover(
					aps,
					nil,
					true,
				),
				discovering.NewPairsDiscover(
					true,
					pairs,
				),
			},
		)
		if useHoper {
			hopper := wifi.NewHopper(handle, iface, true, false, time.Second, func(channel int, freq int) {
				log.Debugf("channel change to: %d/%d\n", channel, freq)
			})
			go func() {
				log.Error(hopper.Start(ctx))
			}()
		}

		go func() {
			for {
				select {
				case ap := <-aps:
					apCache.Store(ap.BSSID.String(), ap)
					log.Info("ap: ", ap, " ", manuf.ManufLookup(ap.BSSID))

				case pair := <-pairs:

					ssid := ""
					if ap, ok := apCache.Load(pair.BssidTo.String()); ok {
						ssid = ap.(discovering.AccessPointInfo).SSID
					}
					if ap, ok := apCache.Load(pair.BssidTo.String()); ok {
						ssid = ap.(discovering.AccessPointInfo).SSID
					}
					pairsCache.Store(pair.BssidFrom.String(), pair)

					log.Infof(
						"pair: [%s] %s (%s) -> %s (%s) chan %d [%d]\n",
						ssid,
						pair.BssidFrom,
						manuf.ManufLookup(pair.BssidFrom),
						pair.BssidTo,
						manuf.ManufLookup(pair.BssidTo),
						pair.Channel,
						pair.DBMAntennaSignal,
					)
				}
			}

		}()

		go func() {
			log.Error(sniffer.Start(ctx))
		}()

		s := make(chan os.Signal, 1)
		signal.Notify(s, syscall.SIGTERM, syscall.SIGINT)
		<-s
		return nil
	},
}

func init() {
	rootCmd.AddCommand(listenCmd)
	listenCmd.Flags().BoolP(FlagListenCmdUseHopper, "", true, "iterate over wifi channels")
}
