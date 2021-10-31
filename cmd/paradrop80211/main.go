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
var clientCache sync.Map

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

	clients := make(chan discovering.ClientInfo, 1)
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
			discovering.NewClientsDiscover(
				true,
				clients,
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
				fmt.Println(ap, manuf.ManufLookup(ap.BSSID))

			case client := <-clients:
				ap, ok := apCache.Load(client.AccessPointBssid.String())
				ssid := ""
				if ok {
					ssid = ap.(discovering.AccessPointInfo).SSID
				}
				clientCache.Store(client.ClientBssid.String(), client)
				fmt.Println(client, manuf.ManufLookup(client.ClientBssid), ssid, manuf.ManufLookup(client.AccessPointBssid))
			}
		}

	}()
	//go func() {
	//	for {
	//		<-time.After(time.Second * 5)
	//		apCache.Range(func(key, apI interface{}) bool {
	//			ap := apI.(discovering.AccessPointInfo)
	//			fmt.Println(ap)
	//
	//			return true
	//		})
	//		clientCache.Range(func(key, clientI interface{}) bool {
	//			client := clientI.(discovering.ClientInfo)
	//			apInfo, ok := apCache.Load(client.AccessPointBssid.String())
	//			ssid := ""
	//			if ok {
	//				ssid = apInfo.(discovering.AccessPointInfo).SSID
	//			}
	//			fmt.Println(client, ssid)
	//
	//			return true
	//		})
	//	}
	//}()

	go func() {
		fmt.Println(sniffer.Start(ctx))
	}()

	<-make(chan struct{})
}
