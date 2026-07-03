package collector

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"PacketYeeter/pkg/collector/ebpf"
)

const managementReadTimeout = 5 * time.Second

type aiSummary struct {
	DetectionsByIP   map[string]int `json:"detections_by_ip"`
	DetectionsByJA4H map[string]int `json:"detections_by_ja4h"`
	DetectionsByASN  map[string]int `json:"detections_by_asn"`
}

type botStats struct {
	TotalDetections    int            `json:"total_detections"`
	ByCategory         map[string]int `json:"by_category"`
	ByVerification     map[string]int `json:"by_verification"`
	BehavioralPatterns map[string]int `json:"behavioral_patterns"`
}

func (c *Collector) startManagementSocket() error {
	if err := prepareUnixSocket(c.Config.SocketPath); err != nil {
		return err
	}

	listener, err := net.Listen("unix", c.Config.SocketPath)
	if err != nil {
		return err
	}
	c.managementListener = listener

	c.wg.Add(1)
	go c.serveManagementSocket(listener)

	c.Logger.WithField("socket", c.Config.SocketPath).Info("Started management socket")
	return nil
}

func (c *Collector) stopManagementSocket() {
	if c.managementListener != nil {
		if err := c.managementListener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			c.Logger.WithError(err).Warn("Management socket close error")
		}
		c.managementListener = nil
	}
	if c.Config.SocketPath != "" {
		if err := os.Remove(c.Config.SocketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			c.Logger.WithError(err).WithField("socket", c.Config.SocketPath).Warn("Failed to remove management socket")
		}
	}
}

func (c *Collector) serveManagementSocket(listener net.Listener) {
	defer c.wg.Done()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || (c.ctx != nil && c.ctx.Err() != nil) {
				return
			}
			c.Logger.WithError(err).Warn("Management socket accept error")
			continue
		}

		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			c.handleManagementConnection(conn)
		}()
	}
}

func (c *Collector) handleManagementConnection(conn net.Conn) {
	defer conn.Close()

	if err := conn.SetReadDeadline(time.Now().Add(managementReadTimeout)); err != nil {
		c.Logger.WithError(err).Debug("Failed to set management socket read deadline")
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		c.Logger.WithError(err).Debug("Failed to read management command")
		return
	}

	command := strings.ToUpper(strings.TrimSpace(string(buf[:n])))
	if err := json.NewEncoder(conn).Encode(c.managementResponse(command)); err != nil {
		c.Logger.WithError(err).Debug("Failed to write management response")
	}
}

func (c *Collector) managementResponse(command string) any {
	switch command {
	case "LIST":
		list := ebpf.BlockedIPList{
			IPv4:        []ebpf.BlockedIPInfo{},
			IPv6:        []ebpf.BlockedIPInfo{},
			MonitorMode: false,
		}
		if c.Maps != nil {
			if c.Maps.BlockedIPs != nil && c.Maps.BlockedIPsV6 != nil {
				list.IPv4, list.IPv6 = c.Maps.ListBlockedIPs(c.Config.BlockDuration)
			}
			list.MonitorMode = c.Maps.DryRun
		}
		return list
	case "REPUTATION":
		return map[string]any{}
	case "AI":
		return aiSummary{
			DetectionsByIP:   map[string]int{},
			DetectionsByJA4H: map[string]int{},
			DetectionsByASN:  map[string]int{},
		}
	case "BOTS":
		return botStats{
			ByCategory:         map[string]int{},
			ByVerification:     map[string]int{},
			BehavioralPatterns: map[string]int{},
		}
	default:
		return map[string]string{"error": fmt.Sprintf("unknown command %q", command)}
	}
}

func prepareUnixSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("%s exists and is not a unix socket", path)
	}

	conn, err := net.DialTimeout("unix", path, 100*time.Millisecond)
	if err == nil {
		conn.Close()
		return fmt.Errorf("%s is already in use", path)
	}
	return os.Remove(path)
}
