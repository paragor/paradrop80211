package wifi

import (
	"context"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/paragor/paradrop80211/pkg/packets"
)

type PacketProcessor interface {
	Process(radiotap *layers.RadioTap, dot11 *layers.Dot11, packet gopacket.Packet)
}

type Sniffer struct {
	handle           *pcap.Handle
	PacketProcessors []PacketProcessor
}

func NewSniffer(handle *pcap.Handle, packetProcessors []PacketProcessor) *Sniffer {
	return &Sniffer{handle: handle, PacketProcessors: packetProcessors}
}

func (s *Sniffer) Start(ctx context.Context) error {
	packetsFlow := gopacket.NewPacketSource(s.handle, s.handle.LinkType()).Packets()
	for {
		select {
		case packet, isOpen := <-packetsFlow:
			if !isOpen {
				return nil
			}
			if packet == nil {
				continue
			}

			if ok, radiotap, dot11 := packets.Dot11Parse(packet); ok {
				if !dot11.ChecksumValid() {
					continue
				}

				for _, processor := range s.PacketProcessors {
					processor.Process(radiotap, dot11, packet)
				}
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
