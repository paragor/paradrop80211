package packets

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
)

func Dot11Freq2Chan(freq int) int {
	if freq <= 2472 {
		return ((freq - 2412) / 5) + 1
	} else if freq == 2484 {
		return 14
	} else if freq >= 5035 && freq <= 5865 {
		return ((freq - 5035) / 5) + 7
	} else if freq >= 5875 && freq <= 5895 {
		return 177
	}
	return 0
}

func Dot11Chan2Freq(channel int) int {
	if channel <= 13 {
		return ((channel - 1) * 5) + 2412
	} else if channel == 14 {
		return 2484
	} else if channel <= 173 {
		return ((channel - 7) * 5) + 5035
	} else if channel == 177 {
		return 5885
	}

	return 0
}

func Dot11Parse(packet gopacket.Packet) (ok bool, radiotap *layers.RadioTap, dot11 *layers.Dot11) {
	ok = false
	radiotap = nil
	dot11 = nil

	radiotapLayer := packet.Layer(layers.LayerTypeRadioTap)
	if radiotapLayer == nil {
		return
	}
	radiotap, ok = radiotapLayer.(*layers.RadioTap)
	if !ok || radiotap == nil {
		return
	}

	dot11Layer := packet.Layer(layers.LayerTypeDot11)
	if dot11Layer == nil {
		ok = false
		return
	}

	dot11, ok = dot11Layer.(*layers.Dot11)
	return
}
func NewDot11Deauth(a1 net.HardwareAddr, a2 net.HardwareAddr, a3 net.HardwareAddr, seq uint16) ([]byte, error) {
	return Serialize(
		&layers.RadioTap{},
		&layers.Dot11{
			Address1:       a1,
			Address2:       a2,
			Address3:       a3,
			Type:           layers.Dot11TypeMgmtDeauthentication,
			SequenceNumber: seq,
		},
		&layers.Dot11MgmtDeauthentication{
			Reason: layers.Dot11ReasonClass2FromNonAuth,
		},
	)
}

func Dot11Info(id layers.Dot11InformationElementID, info []byte) *layers.Dot11InformationElement {
	return &layers.Dot11InformationElement{
		ID:     id,
		Length: uint8(len(info) & 0xff),
		Info:   info,
	}
}
func NewDot11ProbeRequest(staMac net.HardwareAddr, seq uint16, ssid string, channel int) ([]byte, error) {
	stack := []gopacket.SerializableLayer{
		&layers.RadioTap{},
		&layers.Dot11{
			Address1:       BroadcastHw,
			Address2:       staMac,
			Address3:       BroadcastHw,
			Type:           layers.Dot11TypeMgmtProbeReq,
			SequenceNumber: seq,
		},
		&layers.Dot11InformationElement{
			ID:     layers.Dot11InformationElementIDSSID,
			Length: uint8(len(ssid) & 0xff),
			Info:   []byte(ssid),
		},
		Dot11Info(layers.Dot11InformationElementIDRates, []byte{0x82, 0x84, 0x8b, 0x96}),
		Dot11Info(layers.Dot11InformationElementIDESRates, []byte{0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c}),
		Dot11Info(layers.Dot11InformationElementIDDSSet, []byte{byte(channel & 0xff)}),
		Dot11Info(layers.Dot11InformationElementIDHTCapabilities, []byte{0x2d, 0x40, 0x1b, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),
		Dot11Info(layers.Dot11InformationElementIDExtCapability, []byte{0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x00, 0x40}),
		Dot11Info(0xff /* HE Capabilities */, []byte{0x23, 0x01, 0x08, 0x08, 0x18, 0x00, 0x80, 0x20, 0x30, 0x02, 0x00, 0x0d, 0x00, 0x9f, 0x08, 0x00, 0x00, 0x00, 0xfd, 0xff, 0xfd, 0xff, 0x39, 0x1c, 0xc7, 0x71, 0x1c, 0x07}),
	}

	return Serialize(stack...)
}
func Dot11ParseIDSSID(packet gopacket.Packet) (string, bool) {
	for _, layer := range packet.Layers() {
		if layer.LayerType() == layers.LayerTypeDot11InformationElement {
			dot11info, ok := layer.(*layers.Dot11InformationElement)
			if ok && dot11info.ID == layers.Dot11InformationElementIDSSID {
				if len(dot11info.Info) == 0 {
					return "<hidden>", true
				}
				return string(dot11info.Info), true
			}
		}
	}

	return "", false
}
func Dot11ParseDSSet(packet gopacket.Packet) (int, bool) {
	for _, layer := range packet.Layers() {
		info, ok := layer.(*layers.Dot11InformationElement)
		if ok {
			if info.ID == layers.Dot11InformationElementIDDSSet {
				channel, err := Dot11InformationElementIDDSSetDecode(info.Info)
				return channel, err == nil
			}
		}
	}

	return 0, false
}
func Dot11InformationElementIDDSSetDecode(buf []byte) (channel int, err error) {
	err = canParse("DSSet.channel", buf, 1)
	if err != nil {
		return 0, err
	}

	return int(buf[0]), nil
}
func canParse(what string, buf []byte, need int) error {
	available := len(buf)
	if need > available {
		return fmt.Errorf("malformed 802.11 packet, could not parse %s: needed %d bytes but only %d are available.", what, need, available)
	}
	return nil
}

