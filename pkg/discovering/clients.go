package discovering

import (
	"bytes"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/paragor/paradrop80211/pkg/packets"
	"net"
)

type ClientsDiscover struct {
	//todo утечка памяти?
	discovered     map[string]ClientInfo
	withCache      bool
	clientInfoChan chan<- ClientInfo
}

func NewClientsDiscover(withCache bool, clientInfoChan chan<- ClientInfo) *ClientsDiscover {
	return &ClientsDiscover{withCache: withCache, clientInfoChan: clientInfoChan, discovered: map[string]ClientInfo{}}
}

type ClientInfo struct {
	ClientBssid      net.HardwareAddr
	AccessPointBssid net.HardwareAddr
	Frequency        int
	Channel          int
	DBMAntennaSignal int8
}

func IsEqualsClientInfo(a, b ClientInfo) bool {
	return bytes.Equal(a.ClientBssid, b.ClientBssid) &&
		bytes.Equal(a.AccessPointBssid, b.AccessPointBssid) &&
		a.Frequency == b.Frequency &&
		a.Channel == b.Channel
}

func (d *ClientsDiscover) Process(radiotap *layers.RadioTap, dot11 *layers.Dot11, packet gopacket.Packet) {
	// only check data packets of connected stations
	if dot11.Type.MainType() != layers.Dot11TypeData {
		return
	}

	apBssid := dot11.Address1
	clientBssid := dot11.Address2

	clientInfo := ClientInfo{
		ClientBssid:      clientBssid,
		AccessPointBssid: apBssid,
		Frequency:        int(radiotap.ChannelFrequency),
		Channel:          packets.Dot11Freq2Chan(int(radiotap.ChannelFrequency)),
		DBMAntennaSignal: radiotap.DBMAntennaSignal,
	}

	if d.withCache {
		if IsEqualsClientInfo(d.discovered[clientBssid.String()], clientInfo) {
			return
		}
		d.discovered[clientBssid.String()] = clientInfo
	}
	d.clientInfoChan <- clientInfo
}
