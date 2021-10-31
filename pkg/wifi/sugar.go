package wifi

import (
	"fmt"
	"github.com/google/gopacket/pcap"
	"time"
)


func injectPacket(handle *pcap.Handle, data []byte) error {
	if err := handle.WritePacketData(data); err != nil {
		return fmt.Errorf("could not inject WiFi packet: %s", err)
	}
	// let the network card breath a little
	time.Sleep(time.Millisecond)
	return nil
}

