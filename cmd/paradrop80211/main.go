package main

import (
	"context"
	"fmt"
	"github.com/google/gopacket/pcap"
	"github.com/paragor/paradrop80211/pkg/discovering"
	"github.com/paragor/paradrop80211/pkg/manuf"
	"github.com/paragor/paradrop80211/pkg/wifi"
	"os"
	"sync"
	"time"
)

var apCache sync.Map
var pairsCache sync.Map

func main() {
	iface := os.Getenv("IFACE")
	if iface == "" {
		iface = "wlp3s0mon"
	}

	handle, err := pcap.OpenLive(iface, 65536, true, 500*time.Millisecond)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	pairs := make(chan discovering.PairInfo, 1)
	aps := make(chan discovering.AccessPointInfo, 1)
	ctx, cancel := context.WithCancel(context.Background())
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
	hopper := wifi.NewHopper(handle, iface, true, false, time.Second, func(channel int, freq int) {
		fmt.Printf("channel change to: %d/%d\n", channel, freq)
	})
	go func() {
		fmt.Println(hopper.Start(ctx))
	}()

	go func() {
		for {
			select {
			case ap := <-aps:
				apCache.Store(ap.BSSID.String(), ap)
				fmt.Println("ap:   ", ap, manuf.ManufLookup(ap.BSSID))

			case pair := <-pairs:

				ssid := ""
				if ap, ok := apCache.Load(pair.BssidTo.String()); ok {
					ssid = ap.(discovering.AccessPointInfo).SSID
				}
				if ap, ok := apCache.Load(pair.BssidTo.String()); ok {
					ssid = ap.(discovering.AccessPointInfo).SSID
				}
				pairsCache.Store(pair.BssidFrom.String(), pair)

				fmt.Printf(
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
		fmt.Println(sniffer.Start(ctx))
	}()

	<-make(chan struct{})
}
