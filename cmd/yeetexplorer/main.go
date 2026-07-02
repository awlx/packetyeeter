package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

var (
	SocketPath string
)

func formatSignalType(sigType string) string {
	formatMap := map[string]string{
		"ua_suspicious":           "Suspicious User-Agent",
		"missing_accept_language": "Missing Accept-Language",
		"missing_accept_encoding": "Missing Accept-Encoding",
		"no_cookies":              "No Cookies",
		"no_referer":              "No Referer",
		"missing_ja4h":            "Missing JA4H",
		"honeypot":                "Honeypot Access",
		"numeric_seq":             "Numeric Sequence",
		"alpha_seq":               "Alpha Sequence",
		"proxy_lag":               "Proxy Lag (Time Mismatch)",
		"bot_ua":                  "Bot User-Agent",
		"high_latency":            "High Latency",
		"latency_mismatch":        "Latency Mismatch",
		"high_frequency":          "High Frequency",
		"ja4t_abuse":              "JA4T Abuse Pattern",
		"ja4t_suspicious":         "JA4T Suspicious",
		"reputation_offense":      "Reputation Offense",
	}
	if formatted, ok := formatMap[sigType]; ok {
		return formatted
	}
	return sigType
}

func formatSignalSource(source string) string {
	formatMap := map[string]string{
		"spoe":        "HAProxy SPOE (Layer 7)",
		"fingerprint": "TCP Fingerprinting (Layer 4)",
		"tcp":         "TCP Monitor",
		"udp":         "UDP Monitor",
		"icmp":        "ICMP Monitor",
		"reputation":  "Reputation Engine",
	}
	if formatted, ok := formatMap[source]; ok {
		return formatted
	}
	return source
}

func formatBotCategory(category string) string {
	formatMap := map[string]string{
		"ai_crawler_verified": "🤖 AI Crawler (Verified)",
		"ai_crawler_unknown":  "🤖 AI Crawler (Unverified)",
		"search_engine":       "🔍 Search Engine (Verified)",
		"search_unknown":      "🔍 Search Engine (Unverified)",
		"monitoring":          "📊 Monitoring Bot",
		"scanner":             "🔎 Scanner",
		"script":              "📜 Script/Automation",
		"scraper":             "🕷️ Web Scraper",
		"ddos":                "💥 DDoS Bot",
		"legitimate":          "✅ Legitimate Bot",
		"malicious":           "❌ Malicious Bot",
		"unknown":             "❓ Unknown",
	}
	if formatted, ok := formatMap[category]; ok {
		return formatted
	}
	return category
}

func formatVerificationStatus(status string) string {
	formatMap := map[string]string{
		"verified": "✅ Verified",
		"failed":   "❌ Failed",
		"skipped":  "⏭️ Skipped",
		"unknown":  "❓ Unknown",
	}
	if formatted, ok := formatMap[status]; ok {
		return formatted
	}
	return status
}

type SignalEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"`
	Source    string    `json:"source"`
	IP        string    `json:"ip,omitempty"`
	ASN       string    `json:"asn,omitempty"`
	Org       string    `json:"org,omitempty"`
	JA4H      string    `json:"ja4h,omitempty"`
	Weight    float64   `json:"weight"`
	Reason    string    `json:"reason,omitempty"`
}

type BehavioralSummary struct {
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
	SignalRate      float64   `json:"signal_rate"`
	SignalDiversity float64   `json:"signal_diversity"`
	SourceDiversity float64   `json:"source_diversity"`
	IsPersistent    bool      `json:"is_persistent"`
	IsHighFrequency bool      `json:"is_high_frequency"`
	IsBursty        bool      `json:"is_bursty"`
}

type EntityDetails struct {
	Key                string             `json:"key"`
	Type               string             `json:"type"`
	Signals            uint64             `json:"signals"`
	Detections         uint64             `json:"detections"`
	ReputationScore    float64            `json:"reputation_score"`
	EWMA               float64            `json:"ewma"`
	IsBlocked          bool               `json:"is_blocked"`
	BlockExpiresAt     *time.Time         `json:"block_expires_at,omitempty"`
	BotCategory        string             `json:"bot_category,omitempty"`
	VerificationStatus string             `json:"verification_status,omitempty"`
	BlockReason        string             `json:"block_reason,omitempty"`
	Confidence         float64            `json:"confidence,omitempty"`
	Behavioral         *BehavioralSummary `json:"behavioral,omitempty"`
	RecentSignals      []SignalEvent      `json:"recent_signals"`
	RelatedEntities    map[string]int     `json:"related_entities"`
	SignalsByType      map[string]uint64  `json:"signals_by_type"`
	SignalsBySource    map[string]uint64  `json:"signals_by_source"`
}

type ExploreResponse struct {
	Entities []EntitySummary `json:"entities"`
}

type EntitySummary struct {
	Key             string  `json:"key"`
	Type            string  `json:"type"`
	Signals         uint64  `json:"signals"`
	Detections      uint64  `json:"detections"`
	ReputationScore float64 `json:"reputation_score"`
	EWMA            float64 `json:"ewma"`
}

func main() {
	flag.StringVar(&SocketPath, "sock", "/var/run/packetyeeter.sock", "Path to PacketYeeter socket")
	flag.Parse()

	app := tview.NewApplication()
	done := make(chan bool)

	// Entity list (left panel)
	entityList := tview.NewTable().
		SetBorders(false).
		SetSelectable(true, false)
	entityList.SetBorder(true).SetTitle("Entities (↑↓ to select, Enter for details)")

	// Details view (right panel)
	detailsView := tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true)
	detailsView.SetBorder(true).SetTitle("Details")

	// Signal stream (bottom panel)
	signalStream := tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true).
		SetMaxLines(100).
		SetChangedFunc(func() {
			app.Draw()
		})
	signalStream.SetBorder(true).SetTitle("Live Signal Stream")

	// Filter input
	filterInput := tview.NewInputField().
		SetLabel("Filter: ").
		SetFieldWidth(30)
	filterInput.SetBorder(true)

	// Status bar
	statusBar := tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignLeft)
	statusBar.SetText("[yellow]Connecting to PacketYeeter...[white]")

	// Layout
	leftPanel := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(filterInput, 3, 0, false).
		AddItem(entityList, 0, 1, true)

	mainContent := tview.NewFlex().
		AddItem(leftPanel, 0, 1, true).
		AddItem(detailsView, 0, 2, false)

	root := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(mainContent, 0, 3, true).
		AddItem(signalStream, 10, 0, false).
		AddItem(statusBar, 1, 0, false)

	// Load entities
	entities := []EntitySummary{}
	filter := ""
	currentPage := 0
	pageSize := 100

	// Initialize table with header
	entityList.SetCell(0, 0, tview.NewTableCell("Type").SetTextColor(tcell.ColorYellow).SetSelectable(false))
	entityList.SetCell(0, 1, tview.NewTableCell("Entity").SetTextColor(tcell.ColorYellow).SetSelectable(false))
	entityList.SetCell(0, 2, tview.NewTableCell("Signals").SetTextColor(tcell.ColorYellow).SetSelectable(false))
	entityList.SetCell(0, 3, tview.NewTableCell("Detections").SetTextColor(tcell.ColorYellow).SetSelectable(false))
	entityList.SetCell(0, 4, tview.NewTableCell("Reputation").SetTextColor(tcell.ColorYellow).SetSelectable(false))
	entityList.SetCell(0, 5, tview.NewTableCell("EWMA").SetTextColor(tcell.ColorYellow).SetSelectable(false))
	entityList.SetCell(1, 1, tview.NewTableCell("Loading...").SetTextColor(tcell.ColorGray))

	updateEntityList := func() {
		// Header
		entityList.Clear()
		entityList.SetCell(0, 0, tview.NewTableCell("Type").SetTextColor(tcell.ColorYellow).SetSelectable(false))
		entityList.SetCell(0, 1, tview.NewTableCell("Entity").SetTextColor(tcell.ColorYellow).SetSelectable(false))
		entityList.SetCell(0, 2, tview.NewTableCell("Signals").SetTextColor(tcell.ColorYellow).SetSelectable(false))
		entityList.SetCell(0, 3, tview.NewTableCell("Detections").SetTextColor(tcell.ColorYellow).SetSelectable(false))
		entityList.SetCell(0, 4, tview.NewTableCell("Reputation").SetTextColor(tcell.ColorYellow).SetSelectable(false))
		entityList.SetCell(0, 5, tview.NewTableCell("EWMA").SetTextColor(tcell.ColorYellow).SetSelectable(false))

		// Filter entities
		filtered := []EntitySummary{}
		for _, e := range entities {
			if filter == "" || strings.Contains(strings.ToLower(e.Key), strings.ToLower(filter)) {
				filtered = append(filtered, e)
			}
		}

		// Calculate pagination
		totalPages := (len(filtered) + pageSize - 1) / pageSize
		if totalPages == 0 {
			totalPages = 1
		}
		if currentPage >= totalPages {
			currentPage = totalPages - 1
		}
		if currentPage < 0 {
			currentPage = 0
		}

		start := currentPage * pageSize
		end := start + pageSize
		if end > len(filtered) {
			end = len(filtered)
		}

		row := 1
		for i := start; i < end; i++ {
			e := filtered[i]

			typeColor := tcell.ColorWhite
			switch e.Type {
			case "ip":
				typeColor = tcell.ColorGreen
			case "asn":
				typeColor = tcell.ColorBlue
			case "ja4h":
				typeColor = tcell.ColorPurple
			}

			repColor := tcell.ColorGreen
			if e.ReputationScore > 50 {
				repColor = tcell.ColorYellow
			}
			if e.ReputationScore > 100 {
				repColor = tcell.ColorRed
			}

			entityList.SetCell(row, 0, tview.NewTableCell(e.Type).SetTextColor(typeColor))
			entityList.SetCell(row, 1, tview.NewTableCell(e.Key).SetTextColor(tcell.ColorWhite))
			entityList.SetCell(row, 2, tview.NewTableCell(fmt.Sprintf("%d", e.Signals)).SetTextColor(tcell.ColorAqua))
			entityList.SetCell(row, 3, tview.NewTableCell(fmt.Sprintf("%d", e.Detections)).SetTextColor(tcell.ColorRed))
			entityList.SetCell(row, 4, tview.NewTableCell(fmt.Sprintf("%.1f", e.ReputationScore)).SetTextColor(repColor))
			entityList.SetCell(row, 5, tview.NewTableCell(fmt.Sprintf("%.2f", e.EWMA)).SetTextColor(tcell.ColorWhite))

			row++
		}

		// Update title with pagination info
		entityList.SetTitle(fmt.Sprintf("Entities (Page %d/%d) [%d-%d of %d] (↑↓ navigate, ← → page, Enter details)",
			currentPage+1, totalPages, start+1, end, len(filtered)))
	}

	loadEntities := func() {
		conn, err := net.DialTimeout("unix", SocketPath, 5*time.Second)
		if err != nil {
			statusBar.SetText(fmt.Sprintf("[red]Connection failed: %v[white]", err))
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))

		if _, err := conn.Write([]byte("EXPLORE")); err != nil {
			statusBar.SetText(fmt.Sprintf("[red]Write failed: %v[white]", err))
			return
		}

		var response ExploreResponse
		if err := json.NewDecoder(conn).Decode(&response); err != nil {
			statusBar.SetText(fmt.Sprintf("[red]Failed to read: %v[white]", err))
			return
		}

		// Sort by signals descending
		entities = response.Entities
		sort.Slice(entities, func(i, j int) bool {
			return entities[i].Signals > entities[j].Signals
		})

		updateEntityList()
		statusBar.SetText(fmt.Sprintf("[green]Loaded %d entities[white] | 'r' refresh | '← →' page | '/' filter | 'q' quit", len(entities)))
	}

	loadDetails := func(key, entityType string) {
		conn, err := net.DialTimeout("unix", SocketPath, 5*time.Second)
		if err != nil {
			detailsView.SetText(fmt.Sprintf("[red]Connection failed: %v", err))
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))

		if _, err := conn.Write([]byte(fmt.Sprintf("EXPLORE_DETAIL:%s:%s", entityType, key))); err != nil {
			detailsView.SetText(fmt.Sprintf("[red]Write failed: %v", err))
			return
		}

		var details EntityDetails
		if err := json.NewDecoder(conn).Decode(&details); err != nil {
			detailsView.SetText(fmt.Sprintf("[red]Failed to read: %v", err))
			return
		}

		var output strings.Builder
		output.WriteString(fmt.Sprintf("[yellow]Entity:[white] %s\n", details.Key))
		output.WriteString(fmt.Sprintf("[yellow]Type:[white] %s\n", details.Type))
		output.WriteString(fmt.Sprintf("[yellow]Signals:[white] %d\n", details.Signals))
		output.WriteString(fmt.Sprintf("[yellow]Detections:[white] %d\n", details.Detections))
		output.WriteString(fmt.Sprintf("[yellow]Reputation Score:[white] %.2f\n", details.ReputationScore))
		output.WriteString(fmt.Sprintf("[yellow]EWMA Baseline:[white] %.4f\n", details.EWMA))

		// Show bot detection info
		if details.BotCategory != "" {
			output.WriteString(fmt.Sprintf("[yellow]Bot Category:[white] %s\n", formatBotCategory(details.BotCategory)))
		}
		if details.VerificationStatus != "" {
			output.WriteString(fmt.Sprintf("[yellow]Verification:[white] %s\n", formatVerificationStatus(details.VerificationStatus)))
		}
		if details.Confidence > 0 {
			confidenceColor := "green"
			if details.Confidence > 0.7 {
				confidenceColor = "red"
			} else if details.Confidence > 0.5 {
				confidenceColor = "yellow"
			}
			output.WriteString(fmt.Sprintf("[yellow]Confidence:[%s] %.1f%%[white]\n", confidenceColor, details.Confidence*100))
		}

		// Show behavioral profile
		if details.Behavioral != nil {
			output.WriteString("\n[yellow]Behavioral Profile:[white]\n")
			output.WriteString(fmt.Sprintf("  First Seen: %s\n", details.Behavioral.FirstSeen.Format("2006-01-02 15:04:05")))
			output.WriteString(fmt.Sprintf("  Last Seen: %s\n", details.Behavioral.LastSeen.Format("2006-01-02 15:04:05")))
			output.WriteString(fmt.Sprintf("  Signal Rate: %.2f signals/min\n", details.Behavioral.SignalRate))
			output.WriteString(fmt.Sprintf("  Signal Diversity: %.0f types\n", details.Behavioral.SignalDiversity))
			output.WriteString(fmt.Sprintf("  Source Diversity: %.0f sources\n", details.Behavioral.SourceDiversity))

			var patterns []string
			if details.Behavioral.IsPersistent {
				patterns = append(patterns, "[blue]Persistent[white]")
			}
			if details.Behavioral.IsHighFrequency {
				patterns = append(patterns, "[red]High Frequency[white]")
			}
			if details.Behavioral.IsBursty {
				patterns = append(patterns, "[purple]Bursty[white]")
			}
			if len(patterns) > 0 {
				output.WriteString(fmt.Sprintf("  Patterns: %s\n", strings.Join(patterns, ", ")))
			}
		}

		// Show blocked status
		if details.IsBlocked {
			if details.BlockExpiresAt != nil {
				timeLeft := time.Until(*details.BlockExpiresAt)
				if timeLeft > 0 {
					output.WriteString(fmt.Sprintf("\n[red]⚠ BLOCKED[white] - expires in %s (at %s)\n",
						timeLeft.Round(time.Second),
						details.BlockExpiresAt.Format("15:04:05")))
				} else {
					output.WriteString("\n[red]⚠ BLOCKED[white] - expired, pending cleanup\n")
				}
			} else {
				output.WriteString("\n[red]⚠ BLOCKED[white]\n")
			}
		} else {
			output.WriteString("\n[green]✓ Not Blocked[white]\n")
		}

		// Show block reason
		if details.BlockReason != "" {
			output.WriteString(fmt.Sprintf("[yellow]Block Reason:[white]\n%s\n", details.BlockReason))
		}
		output.WriteString("\n")

		// Show signal breakdown by type
		if len(details.SignalsByType) > 0 {
			output.WriteString("[yellow]Signals by Type:[white]\n")
			type kv struct {
				Key   string
				Value uint64
			}
			var sorted []kv
			for k, v := range details.SignalsByType {
				sorted = append(sorted, kv{k, v})
			}
			sort.Slice(sorted, func(i, j int) bool {
				return sorted[i].Value > sorted[j].Value
			})
			for _, item := range sorted {
				output.WriteString(fmt.Sprintf("  %s: %d\n", formatSignalType(item.Key), item.Value))
			}
			output.WriteString("\n")
		}

		// Show signal breakdown by source
		if len(details.SignalsBySource) > 0 {
			output.WriteString("[yellow]Signals by Source:[white]\n")
			type kv struct {
				Key   string
				Value uint64
			}
			var sorted []kv
			for k, v := range details.SignalsBySource {
				sorted = append(sorted, kv{k, v})
			}
			sort.Slice(sorted, func(i, j int) bool {
				return sorted[i].Value > sorted[j].Value
			})
			for _, item := range sorted {
				output.WriteString(fmt.Sprintf("  %s: %d\n", formatSignalSource(item.Key), item.Value))
			}
			output.WriteString("\n")
		}

		if len(details.RecentSignals) > 0 {
			output.WriteString("[yellow]Recent Signals:[white]\n")
			for i, sig := range details.RecentSignals {
				if i >= 20 {
					break
				}
				color := "white"
				switch sig.Type {
				case "proxy_lag":
					color = "red"
				case "ja4t_suspicious":
					color = "purple"
				case "high_latency":
					color = "yellow"
				case "latency_mismatch":
					color = "orange"
				}

				output.WriteString(fmt.Sprintf("  [%s]%s[white] %s (source: %s, weight: %.1f)\n",
					color,
					sig.Timestamp.Format("15:04:05"),
					sig.Type,
					sig.Source,
					sig.Weight))
				if sig.Reason != "" {
					output.WriteString(fmt.Sprintf("    └─ %s\n", sig.Reason))
				}
			}
		}

		if len(details.RelatedEntities) > 0 {
			// Sort by count
			type kv struct {
				Key   string
				Count int
			}
			var sorted []kv
			for k, v := range details.RelatedEntities {
				sorted = append(sorted, kv{k, v})
			}
			sort.Slice(sorted, func(i, j int) bool {
				return sorted[i].Count > sorted[j].Count
			})

			output.WriteString("\n[yellow]Related Entities:[white]\n")
			for i, item := range sorted {
				if i >= 10 {
					break
				}
				output.WriteString(fmt.Sprintf("  %s (%d signals)\n", item.Key, item.Count))
			}
		}

		detailsView.SetText(output.String())
	}

	entityList.SetSelectedFunc(func(row, col int) {
		if row == 0 {
			return
		}

		cell := entityList.GetCell(row, 1)
		if cell != nil {
			key := cell.Text
			typeCell := entityList.GetCell(row, 0)
			entityType := typeCell.Text

			loadDetails(key, entityType)
		}
	})

	filterInput.SetChangedFunc(func(text string) {
		filter = text
		updateEntityList()
	})

	// Key bindings
	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyRune:
			switch event.Rune() {
			case 'q':
				close(done)
				time.Sleep(100 * time.Millisecond) // Give goroutine time to exit
				app.Stop()
				return nil
			case 'r':
				go loadEntities()
				return nil
			case '/':
				app.SetFocus(filterInput)
				return nil
			}
		case tcell.KeyEsc:
			app.SetFocus(entityList)
			return nil
		case tcell.KeyLeft:
			if currentPage > 0 {
				currentPage--
				updateEntityList()
			}
			return nil
		case tcell.KeyRight:
			currentPage++
			updateEntityList()
			return nil
		}
		return event
	})

	// Start signal stream listener
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				conn, err := net.DialTimeout("unix", SocketPath, 2*time.Second)
				if err != nil {
					continue
				}
				conn.SetDeadline(time.Now().Add(5 * time.Second))

				if _, err := conn.Write([]byte("SIGNALS")); err != nil {
					conn.Close()
					continue
				}

				var signals []SignalEvent
				if err := json.NewDecoder(conn).Decode(&signals); err != nil {
					conn.Close()
					continue
				}
				conn.Close()

				if len(signals) > 0 {
					app.QueueUpdateDraw(func() {
						for _, sig := range signals {
							color := "white"
							switch sig.Type {
							case "proxy_lag":
								color = "red"
							case "ja4t_suspicious":
								color = "purple"
							case "high_latency":
								color = "yellow"
							case "latency_mismatch":
								color = "orange"
							}

							entity := sig.IP
							if entity == "" && sig.ASN != "" {
								entity = sig.ASN
							}
							if entity == "" && sig.JA4H != "" {
								entity = sig.JA4H
							}

							fmt.Fprintf(signalStream, "[%s]%s[white] [%s]%s[white] from %s (w:%.1f)\n",
								color,
								sig.Timestamp.Format("15:04:05"),
								color,
								sig.Type,
								entity,
								sig.Weight)
						}
					})
				}
			}
		}
	}()

	// Initial load
	go loadEntities()

	// Set focus on entity list
	app.SetFocus(entityList)

	if err := app.SetRoot(root, true).EnableMouse(true).Run(); err != nil {
		panic(err)
	}
}
