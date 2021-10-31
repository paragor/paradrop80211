package packets

import (
	"github.com/google/gopacket"
	"net"
	"strings"
)

const (
	MonitorModeAddress = "0.0.0.0"
	BroadcastSuffix    = ".255"
	BroadcastMac       = "ff:ff:ff:ff:ff:ff"
	IPv4MulticastStart = "01:00:5e:00:00:00"
	IPv4MulticastEnd   = "01:00:5e:7f:ff:ff"
)

var (
	BroadcastHw        = []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
)

func IsZeroMac(mac net.HardwareAddr) bool {
	for _, b := range mac {
		if b != 0x00 {
			return false
		}
	}
	return true
}

func IsBroadcastMac(mac net.HardwareAddr) bool {
	for _, b := range mac {
		if b != 0xff {
			return false
		}
	}
	return true
}


func Serialize(layers ...gopacket.SerializableLayer) ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(
		buf,
		gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		layers...,
	)
	return buf.Bytes(), err
}

func NormalizeMac(mac string) string {
	var parts []string
	if strings.ContainsRune(mac, '-') {
		parts = strings.Split(mac, "-")
	} else {
		parts = strings.Split(mac, ":")
	}

	for i, p := range parts {
		if len(p) < 2 {
			parts[i] = "0" + p
		}
	}
	return strings.ToLower(strings.Join(parts, ":"))
}
