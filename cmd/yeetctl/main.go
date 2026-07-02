package main

import (
	"PacketYeeter/pkg/collector/ebpf"
	"PacketYeeter/pkg/analyzer/reputation"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"time"
)

var (
	SocketPath string
	Command    string
)

type kv struct {
	Key   string
	Count int
}

func sortedEntries(m map[string]int) []kv {
	out := make([]kv, 0, len(m))
	for k, v := range m {
		out = append(out, kv{Key: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Key < out[j].Key
		}
		return out[i].Count > out[j].Count
	})
	return out
}

func main() {
	flag.StringVar(&SocketPath, "sock", "/var/run/packetyeeter.sock", "Path to PacketYeeter socket")
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		fmt.Println("Usage: yeetctl [options] <command>")
		fmt.Println("Commands:")
		fmt.Println("  list       - List blocked IPs")
		fmt.Println("  reputation - List full reputation table")
		fmt.Println("  ai         - Show AI scraper detections summary")
		fmt.Println("  bots       - Show bot categorization summary")
		os.Exit(1)
	}
	Command = args[0]

	conn, err := net.Dial("unix", SocketPath)
	if err != nil {
		fmt.Printf("Failed to connect to PacketYeeter at %s: %v\n", SocketPath, err)
		os.Exit(1)
	}
	defer conn.Close()

	if Command == "list" {
		_, err = conn.Write([]byte("LIST"))
		if err != nil {
			fmt.Printf("Failed to send command: %v\n", err)
			os.Exit(1)
		}

		var list ebpf.BlockedIPList
		if err := json.NewDecoder(conn).Decode(&list); err != nil {
			fmt.Printf("Failed to read response: %v\n", err)
			os.Exit(1)
		}

		if list.MonitorMode {
			fmt.Println("!!! MONITOR MODE ENABLED !!!")
			fmt.Println("These IPs have violated rules and WOULD be blocked, but traffic is currently ALLOWED.")
			fmt.Println("")
		}

		fmt.Println("Blocked IPv4:")
		for _, info := range list.IPv4 {
			fmt.Printf("  - %-15s (TTL: %s)\n", info.IP, info.RemainingTTL)
		}
		if len(list.IPv4) == 0 {
			fmt.Println("  (none)")
		}

		fmt.Println("\nBlocked IPv6:")
		for _, info := range list.IPv6 {
			fmt.Printf("  - %-39s (TTL: %s)\n", info.IP, info.RemainingTTL)
		}
		if len(list.IPv6) == 0 {
			fmt.Println("  (none)")
		}
	} else if Command == "reputation" || Command == "scores" {
		_, err = conn.Write([]byte("REPUTATION"))
		if err != nil {
			fmt.Printf("Failed to send command: %v\n", err)
			os.Exit(1)
		}

		var entries map[string]*reputation.Entry
		if err := json.NewDecoder(conn).Decode(&entries); err != nil {
			fmt.Printf("Failed to read response: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("Reputation Table")
		fmt.Printf("%-40s | %-10s | %-10s | %-20s\n", "Entity", "Score", "Offenses", "Last Seen")
		fmt.Println("-----------------------------------------------------------------------------------------")

		// Sort keys for consistent output
		keys := make([]string, 0, len(entries))
		for k := range entries {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, k := range keys {
			e := entries[k]
			fmt.Printf("%-40s | %-10.2f | %-10d | %-20s\n", k, e.Score, e.Offenses, e.LastSeen.Format(time.RFC822))
		}
	} else if Command == "ai" {
		type AISummary struct {
			DetectionsByIP   map[string]int `json:"detections_by_ip"`
			DetectionsByJA4H map[string]int `json:"detections_by_ja4h"`
			DetectionsByASN  map[string]int `json:"detections_by_asn"`
		}

		_, err = conn.Write([]byte("AI"))
		if err != nil {
			fmt.Printf("Failed to send command: %v\n", err)
			os.Exit(1)
		}

		var summary AISummary
		if err := json.NewDecoder(conn).Decode(&summary); err != nil {
			fmt.Printf("Failed to read response: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("AI Scraper Detections (last run)")
		fmt.Println("By IP:")
		for _, item := range sortedEntries(summary.DetectionsByIP) {
			fmt.Printf("  %-20s %d\n", item.Key, item.Count)
		}
		fmt.Println("\nBy JA4H:")
		for _, item := range sortedEntries(summary.DetectionsByJA4H) {
			fmt.Printf("  %-20s %d\n", item.Key, item.Count)
		}
		fmt.Println("\nBy ASN:")
		for _, item := range sortedEntries(summary.DetectionsByASN) {
			fmt.Printf("  %-20s %d\n", item.Key, item.Count)
		}
	} else if Command == "bots" {
		type BotStats struct {
			TotalDetections    int            `json:"total_detections"`
			ByCategory         map[string]int `json:"by_category"`
			ByVerification     map[string]int `json:"by_verification"`
			BehavioralPatterns map[string]int `json:"behavioral_patterns"`
		}

		_, err = conn.Write([]byte("BOTS"))
		if err != nil {
			fmt.Printf("Failed to send command: %v\n", err)
			os.Exit(1)
		}

		var stats BotStats
		if err := json.NewDecoder(conn).Decode(&stats); err != nil {
			fmt.Printf("Failed to read response: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("Bot Detection Statistics")
		fmt.Printf("\nTotal Detections: %d\n", stats.TotalDetections)

		fmt.Println("\nBy Category:")
		categoryLabels := map[string]string{
			"ai_crawler_verified": "🤖 AI Crawler (Verified)",
			"ai_crawler_unknown":  "🤖 AI Crawler (Unverified)",
			"search_engine":       "🔍 Search Engine",
			"scanner":             "🔎 Scanner",
			"scraper":             "🕷️ Scraper",
			"ddos":                "💥 DDoS",
			"malicious":           "❌ Malicious",
			"legitimate":          "✅ Legitimate",
		}
		for _, item := range sortedEntries(stats.ByCategory) {
			label := categoryLabels[item.Key]
			if label == "" {
				label = item.Key
			}
			fmt.Printf("  %-35s %d\n", label, item.Count)
		}

		fmt.Println("\nVerification Status:")
		for _, item := range sortedEntries(stats.ByVerification) {
			status := item.Key
			switch status {
			case "verified":
				status = "✅ Verified"
			case "failed":
				status = "❌ Failed"
			case "skipped":
				status = "⏭️ Skipped"
			}
			fmt.Printf("  %-20s %d\n", status, item.Count)
		}

		if len(stats.BehavioralPatterns) > 0 {
			fmt.Println("\nBehavioral Patterns:")
			for _, item := range sortedEntries(stats.BehavioralPatterns) {
				pattern := item.Key
				switch pattern {
				case "persistent":
					pattern = "Persistent (>1hr)"
				case "high_frequency":
					pattern = "High Frequency (>10/min)"
				case "bursty":
					pattern = "Bursty (irregular timing)"
				}
				fmt.Printf("  %-30s %d\n", pattern, item.Count)
			}
		}
	} else {
		fmt.Printf("Unknown command: %s\n", Command)
		os.Exit(1)
	}
}
