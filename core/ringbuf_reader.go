package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/cilium/ebpf/ringbuf"
)

type bpfEvent struct {
	Ts      uint64
	SrcIP   uint32
	DstIP   uint32
	SrcIP6  [16]byte
	DstIP6  [16]byte
	SrcPort uint16
	DstPort uint16
	Proto   uint8
	Action  uint8
	Reason  uint8
	Pad     uint8
}

func startRingbufReader(shutdown chan struct{}) {
	if bpfObjs.EventRingbuf == nil {
		log.Println("[RUNTIME] No ringbuf map available")
		ringbufStartupOnce.Do(func() {
			close(ringbufStartupDone)
		})
		return
	}

	rd, err := ringbuf.NewReader(bpfObjs.EventRingbuf)
	if err != nil {
		log.Printf("[RUNTIME] Failed to open ringbuf: %v", err)
		ringbufStartupOnce.Do(func() {
			close(ringbufStartupDone)
		})
		return
	}
	defer rd.Close()

	go func() {
		<-shutdown
		rd.Close()
	}()

	log.Println("[RUNTIME] Ringbuf reader started")
	ringbufStartupOnce.Do(func() {
		close(ringbufStartupDone)
	})

	var sample uint64
	sampleN := uint64(1)
	if config.Security.EventSampleN > 1 {
		sampleN = uint64(config.Security.EventSampleN)
	}

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("[RUNTIME] Ringbuf read error: %v", err)
			continue
		}

		var ev bpfEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &ev); err != nil {
			log.Printf("[RUNTIME] Ringbuf decode error: %v", err)
			continue
		}

		// Sample non-drop events to reduce user-space load.
		if ev.Action == 0 && sampleN > 1 {
			sample++
			if sample%sampleN != 0 {
				continue
			}
		}

		proto := "other"
		switch ev.Proto {
		case 6:
			proto = "tcp"
		case 17:
			proto = "udp"
		case 1:
			proto = "icmp"
		}

		evtType := "XDP"
		if ev.Action == 1 {
			evtType = "XDP_DROP"
		}

		attacker := ipFromUint32(ev.SrcIP)
		targetIP := ipFromUint32(ev.DstIP)
		if attacker == "0.0.0.0" && targetIP == "0.0.0.0" {
			if ip := net.IP(ev.SrcIP6[:]); !ip.IsUnspecified() {
				attacker = ip.String()
			}
			if ip := net.IP(ev.DstIP6[:]); !ip.IsUnspecified() {
				targetIP = ip.String()
			}
		}

		actionLabel := "ALLOW"
		if ev.Action == 1 {
			actionLabel = "DROP"
		}
		reasonLabel := "PASS"
		if ev.Reason == 1 {
			reasonLabel = "BANNED"
		}
		payload := fmt.Sprintf("action=%s(%d) reason=%s(%d)", actionLabel, ev.Action, reasonLabel, ev.Reason)
		if ev.Action == 0 && ev.Reason == 0 {
			payload += " sampled"
		}

		e := Event{
			Timestamp: time.Now().Format(time.RFC3339),
			Attacker:  attacker,
			TargetIP:  targetIP,
			Target:    strconv.Itoa(int(ev.DstPort)),
			Service:   proto,
			Node:      config.NodeName,
			Type:      evtType,
			Payload:   payload,
			Entropy:   0,
			Interface: "xdp",
			JA3:       "",
		}

		emitEvent(e)
	}
}

func waitForRingbufStartup(timeout time.Duration) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-ringbufStartupDone:
	case <-timer.C:
	}
}
