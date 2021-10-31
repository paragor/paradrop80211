package wifi

import (
	"context"
	"github.com/google/gopacket/pcap"
	"github.com/paragor/paradrop80211/pkg/packets"
	"net"
)

type Prober struct {
	handle *pcap.Handle
}

func NewProber(handle *pcap.Handle) *Prober {
	return &Prober{handle: handle}
}

func (p *Prober) Probe(ctx context.Context, staMac net.HardwareAddr, ssid string, currentChannel int) error {
	for seq := uint16(0); seq < 5; seq++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		pkt, err := packets.NewDot11ProbeRequest(staMac, seq, ssid, currentChannel)
		if err != nil {
			return err
		}
		if err := injectPacket(p.handle, pkt); err != nil {
			return err
		}
	}

	return nil
}
