package discovering

import (
	"bytes"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/paragor/paradrop80211/pkg/packets"
	"net"
)

type PairsDiscover struct {
	//todo утечка памяти?
	discovered    map[string]PairInfo
	withCache     bool
	pairsInfoChan chan<- PairInfo
}

func NewPairsDiscover(withCache bool, pairsInfoChan chan<- PairInfo) *PairsDiscover {
	return &PairsDiscover{withCache: withCache, pairsInfoChan: pairsInfoChan, discovered: map[string]PairInfo{}}
}

type PairInfo struct {
	BssidFrom        net.HardwareAddr
	BssidTo          net.HardwareAddr
	Frequency        int
	Channel          int
	DBMAntennaSignal int8
}

func IsEqualsPair(a, b PairInfo) bool {
	return bytes.Equal(a.BssidFrom, b.BssidFrom) &&
		bytes.Equal(a.BssidTo, b.BssidTo) &&
		a.Frequency == b.Frequency &&
		a.Channel == b.Channel
}

func (d *PairsDiscover) Process(radiotap *layers.RadioTap, dot11 *layers.Dot11, packet gopacket.Packet) {
	// only check data packets of connected stations
	if dot11.Type.MainType() != layers.Dot11TypeData {
		return
	}

	bssidFrom := dot11.Address1
	bssidTo := dot11.Address2

	if packets.IsZeroMac(bssidTo) || packets.IsBroadcastMac(bssidTo) {
		return
	}

	pairInfo := PairInfo{
		BssidFrom:        bssidFrom,
		BssidTo:          bssidTo,
		Frequency:        int(radiotap.ChannelFrequency),
		Channel:          packets.Dot11Freq2Chan(int(radiotap.ChannelFrequency)),
		DBMAntennaSignal: radiotap.DBMAntennaSignal,
	}

	if d.withCache {
		if IsEqualsPair(d.discovered[bssidFrom.String()], pairInfo) {
			return
		}
		d.discovered[bssidFrom.String()] = pairInfo
	}
	d.pairsInfoChan <- pairInfo
}
