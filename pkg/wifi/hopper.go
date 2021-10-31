package wifi

import (
	"context"
	"fmt"
	"github.com/google/gopacket/pcap"
	network "github.com/paragor/paradrop80211/pkg/interface"
	"github.com/paragor/paradrop80211/pkg/logger"
	"github.com/paragor/paradrop80211/pkg/packets"
	"strings"
	"time"
)

type OnChannelChange func(channel int, freq int)

type Hopper struct {
	handle          *pcap.Handle
	iface           string
	use24ghz        bool
	use5ghz         bool
	interval        time.Duration
	onChannelChange OnChannelChange
}

func NewHopper(handle *pcap.Handle, iface string, use24ghz bool, use5ghz bool, interval time.Duration, onChannelChange OnChannelChange) *Hopper {
	return &Hopper{
		handle:          handle,
		iface:           iface,
		use24ghz:        use24ghz,
		use5ghz:         use5ghz,
		interval:        interval,
		onChannelChange: onChannelChange,
	}
}

func filterInts(arr []int, isGood func(value int) bool) []int {
	newArr := make([]int, 0, len(arr))
	for _, v := range arr {
		if isGood(v) {
			newArr = append(newArr, v)
		}
	}

	return newArr
}

func (h *Hopper) Start(ctx context.Context) error {
	freqs, err := network.GetSupportedFrequencies(h.iface)
	if err != nil {
		return err
	}

	if !h.use5ghz && !h.use24ghz {
		return fmt.Errorf("wtf what ghz should use if use5ghz=false and use24ghz=false")
	}

	if h.use24ghz != h.use5ghz {
		if h.use24ghz {
			freqs = filterInts(freqs, func(value int) bool {
				return value < 5000
			})
		} else {
			freqs = filterInts(freqs, func(value int) bool {
				return value >= 5000
			})
		}
	}

	ticker := time.NewTicker(h.interval)
	defer ticker.Stop()

	for {
		for i, freq := range freqs {
			channel := packets.Dot11Freq2Chan(freq)
			if err := network.SetInterfaceChannel(h.iface, channel); err != nil {
				if strings.Contains(err.Error(), "Channel is disabled") {
					newFreqs := make([]int, 0, len(freqs)-1)
					newFreqs = append(freqs[:i], freqs[i+1:]...)
					freqs = newFreqs
				} else {
					logger.FromContext(ctx).
						With("channel", channel, "iface", h.iface).
						Warnf("cant set interface channel :%s", err.Error())
					continue
				}
			} else {
				h.onChannelChange(channel, freq)
			}

			select {
			case <-ticker.C:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}

}
