package discovering

import (
	"bytes"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/paragor/paradrop80211/pkg/packets"
	"net"
)

type AccessPointDiscover struct {
	ignoredBSSID net.HardwareAddr
	discovered   map[string]AccessPointInfo
	withCache    bool
	apInfoChan   chan<- AccessPointInfo
}

func NewAccessPointDiscover(apInfoChan chan<- AccessPointInfo, ignoredBSSID net.HardwareAddr, withCache bool) *AccessPointDiscover {
	return &AccessPointDiscover{
		ignoredBSSID: ignoredBSSID,
		apInfoChan:   apInfoChan,
		withCache:    withCache,
		discovered:   map[string]AccessPointInfo{},
	}
}

type AccessPointInfo struct {
	SSID             string
	BSSID            net.HardwareAddr
	Frequency        int
	Channel          int
	DBMAntennaSignal int8
}

func IsEqualsApInfo(a, b AccessPointInfo) bool {
	return bytes.Equal(a.BSSID, b.BSSID) &&
		a.SSID == b.SSID &&
		a.Frequency == b.Frequency &&
		a.Channel == b.Channel
}

func (d *AccessPointDiscover) Process(radiotap *layers.RadioTap, dot11 *layers.Dot11, packet gopacket.Packet) {
	ssid, ok := packets.Dot11ParseIDSSID(packet)
	if !ok {
		return
	}
	from := dot11.Address3
	if len(d.ignoredBSSID) > 0 && bytes.Equal(from, d.ignoredBSSID) {
		return
	}

	if !packets.IsZeroMac(from) && !packets.IsBroadcastMac(from) {
		var frequency int
		if channel, found := packets.Dot11ParseDSSet(packet); found {
			frequency = packets.Dot11Chan2Freq(channel)
		} else {
			frequency = int(radiotap.ChannelFrequency)
		}

		ap := AccessPointInfo{
			SSID:             ssid,
			BSSID:            from,
			Channel:          packets.Dot11Freq2Chan(frequency),
			Frequency:        frequency,
			DBMAntennaSignal: radiotap.DBMAntennaSignal,
		}

		if d.withCache {
			if IsEqualsApInfo(d.discovered[from.String()], ap) {
				return
			}
			d.discovered[from.String()] = ap
		}

		d.apInfoChan <- ap
	}
}
