package main

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"

	"honeymesh/internal/enforcementengine"
)

// ueeKernelAdapter is the checked XDP map boundary for the unified engine.
// Runtime producers must use grants; only this adapter should write ban maps
// after the UEE cutover is complete.
type ueeKernelAdapter struct{}

var _ enforcementengine.Kernel = ueeKernelAdapter{}

func ueeAddress(raw string) (netip.Addr, error) {
	ip, err := netip.ParseAddr(raw)
	if err != nil || !ip.IsValid() || ip.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("invalid exact source address")
	}
	return ip.Unmap(), nil
}

func (ueeKernelAdapter) Apply(raw string) error {
	ip, err := ueeAddress(raw)
	if err != nil {
		return err
	}
	if ip.Is4() {
		if bpfObjs.BanMap == nil {
			return errors.New("IPv4 ban map unavailable")
		}
		return bpfObjs.BanMap.Put(ip.As4(), uint8(1))
	}
	if bpfObjs.BanMapV6 == nil {
		return errors.New("IPv6 ban map unavailable")
	}
	return bpfObjs.BanMapV6.Put(ip.As16(), uint8(1))
}

func (ueeKernelAdapter) Remove(raw string) error {
	ip, err := ueeAddress(raw)
	if err != nil {
		return err
	}
	if ip.Is4() {
		if bpfObjs.BanMap == nil {
			return errors.New("IPv4 ban map unavailable")
		}
		err = bpfObjs.BanMap.Delete(ip.As4())
	} else {
		if bpfObjs.BanMapV6 == nil {
			return errors.New("IPv6 ban map unavailable")
		}
		err = bpfObjs.BanMapV6.Delete(ip.As16())
	}
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}
