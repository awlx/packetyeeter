package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"PacketYeeter/pkg/analyzer/aidetection"
)

// LabeledDetection is a detection event with a human-provided label
type LabeledDetection struct {
	// Original detection fields
	IP              string                           `json:"ip"`
	ASN             string                           `json:"asn,omitempty"`
	Org             string                           `json:"org,omitempty"`
	JA4             string                           `json:"ja4,omitempty"`
	JA4H            string                           `json:"ja4h,omitempty"`
	Timestamp       time.Time                        `json:"timestamp"`
	SignalCount     int                              `json:"signal_count"`
	Confidence      float64                          `json:"confidence"`
	MLConfidence    float64                          `json:"ml_confidence"`
	AutoCategory    aidetection.BotCategory          `json:"auto_category"`
	SignalBreakdown map[aidetection.SignalType]int   `json:"signal_breakdown"`
	SourceBreakdown map[aidetection.SignalSource]int `json:"source_breakdown"`

	// Human labels
	Label           string    `json:"label"`            // "bot", "human", "unknown"
	BotType         string    `json:"bot_type"`         // "scraper", "ddos", "crawler", etc. (if bot)
	Notes           string    `json:"notes"`            // Free-form notes
	LabeledBy       string    `json:"labeled_by"`       // Who labeled this
	LabeledAt       time.Time `json:"labeled_at"`       // When labeled
	LabelConfidence int       `json:"label_confidence"` // 1-5 scale
}

// detectionInput is a detection event to be labeled (analyzer output).
type detectionInput struct {
	IP              string
	ASN             string
	Org             string
	JA4             string
	JA4H            string
	Timestamp       time.Time
	SignalCount     int
	Confidence      float64
	MLConfidence    float64
	AutoCategory    aidetection.BotCategory
	SignalBreakdown map[aidetection.SignalType]int
	SourceBreakdown map[aidetection.SignalSource]int
}

// labelInput holds the answers gathered from the interactive prompt.
type labelInput struct {
	Label      string
	BotType    string
	Notes      string
	Confidence int
}

func main() {
	var (
		inputFile  = flag.String("input", "", "Input JSON file with detections")
		outputFile = flag.String("output", "labeled_dataset.jsonl", "Output JSONL file with labels")
		username   = flag.String("user", os.Getenv("USER"), "Your username for labeling")
		startFrom  = flag.Int("start", 0, "Start from detection N (skip previous)")
		batchSize  = flag.Int("batch", 50, "Number of detections to label per session")
	)
	flag.Parse()

	if *inputFile == "" {
		logrus.Fatal("--input is required")
	}

	// Load detections from input file
	detections, err := loadDetections(*inputFile)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to load detections")
	}
	logrus.Infof("Loaded %d detections from %s", len(detections), *inputFile)

	// Load existing labels if output file exists
	existingLabels := make(map[string]LabeledDetection)
	if _, err := os.Stat(*outputFile); err == nil {
		existingLabels, err = loadLabels(*outputFile)
		if err != nil {
			logrus.WithError(err).Warn("Failed to load existing labels, starting fresh")
		} else {
			logrus.Infof("Loaded %d existing labels", len(existingLabels))
		}
	}

	// Open output file in append mode
	outFile, err := os.OpenFile(*outputFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to open output file")
	}
	defer outFile.Close()
	encoder := json.NewEncoder(outFile)
	reader := bufio.NewReader(os.Stdin)

	// Start labeling
	labeled := 0
	skipped := 0
	for i := *startFrom; i < len(detections) && labeled < *batchSize; i++ {
		det := detections[i]
		key := det.IP + "_" + det.Timestamp.Format(time.RFC3339)
		// Skip if already labeled
		if _, exists := existingLabels[key]; exists {
			skipped++
			continue
		}

		// Display detection
		fmt.Println("\n" + strings.Repeat("=", 80))
		fmt.Printf("Detection #%d/%d\n", i+1, len(detections))
		fmt.Println(strings.Repeat("=", 80))
		fmt.Printf("IP:           %s\n", det.IP)
		fmt.Printf("ASN:          %s (%s)\n", det.ASN, det.Org)
		fmt.Printf("Timestamp:    %s\n", det.Timestamp.Format(time.RFC3339))
		fmt.Printf("Signal Count: %d\n", det.SignalCount)
		fmt.Printf("Confidence:   %.2f\n", det.Confidence)
		fmt.Printf("ML Conf:      %.2f\n", det.MLConfidence)
		fmt.Printf("Auto Category: %s\n", det.AutoCategory)
		fmt.Printf("JA4:          %s\n", det.JA4)
		fmt.Printf("JA4H:         %s\n", det.JA4H)
		fmt.Println("\nSignal Breakdown:")
		for sig, count := range det.SignalBreakdown {
			fmt.Printf("  %-30s: %d\n", sig, count)
		}

		// Get label from user
		label, err := promptLabel(reader)
		if err != nil {
			logrus.WithError(err).Error("Failed to get label")
			continue
		}

		if label.Label == "skip" {
			fmt.Println("Skipped")
			continue
		}
		if label.Label == "quit" {
			fmt.Println("Quitting...")
			break
		}

		// Create labeled detection
		labeledDet := LabeledDetection{
			IP:              det.IP,
			ASN:             det.ASN,
			Org:             det.Org,
			JA4:             det.JA4,
			JA4H:            det.JA4H,
			Timestamp:       det.Timestamp,
			SignalCount:     det.SignalCount,
			Confidence:      det.Confidence,
			MLConfidence:    det.MLConfidence,
			AutoCategory:    det.AutoCategory,
			SignalBreakdown: det.SignalBreakdown,
			SourceBreakdown: det.SourceBreakdown,
			Label:           label.Label,
			BotType:         label.BotType,
			Notes:           label.Notes,
			LabeledBy:       *username,
			LabeledAt:       time.Now(),
			LabelConfidence: label.Confidence,
		}

		// Write to output file
		if err := encoder.Encode(labeledDet); err != nil {
			logrus.WithError(err).Error("Failed to write label")
			continue
		}
		labeled++
		fmt.Printf("✓ Labeled as: %s", label.Label)
		if label.BotType != "" {
			fmt.Printf(" (%s)", label.BotType)
		}
		fmt.Println()
	}

	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Printf("Session complete: %d labeled, %d skipped\n", labeled, skipped)
	fmt.Printf("Total labels in %s: %d\n", *outputFile, len(existingLabels)+labeled)
	fmt.Println(strings.Repeat("=", 80))
}

// promptLabel drives the interactive labeling questions for a single detection.
func promptLabel(reader *bufio.Reader) (labelInput, error) {
	fmt.Println("\nLabel this detection:")
	fmt.Println("  [h] Human (legitimate user)")
	fmt.Println("  [b] Bot (malicious/unwanted)")
	fmt.Println("  [u] Unknown (can't determine)")
	fmt.Println("  [s] Skip")
	fmt.Println("  [q] Quit")
	fmt.Print("\nYour choice: ")
	choice, err := reader.ReadString('\n')
	if err != nil {
		return labelInput{}, err
	}
	choice = strings.TrimSpace(strings.ToLower(choice))

	var label labelInput
	switch choice {
	case "h":
		label.Label = "human"
	case "b":
		label.Label = "bot"
	case "u":
		label.Label = "unknown"
	case "s":
		label.Label = "skip"
		return label, nil
	case "q":
		label.Label = "quit"
		return label, nil
	default:
		return labelInput{}, fmt.Errorf("invalid choice")
	}

	// If bot, ask for bot type
	if label.Label == "bot" {
		fmt.Println("\nBot type:")
		fmt.Println("  [1] Scraper (content extraction)")
		fmt.Println("  [2] DDoS (flood attack)")
		fmt.Println("  [3] Crawler (systematic exploration)")
		fmt.Println("  [4] Spam/Brute force")
		fmt.Println("  [5] Vulnerability scanner")
		fmt.Println("  [6] Other")
		fmt.Print("Bot type: ")
		botChoice, err := reader.ReadString('\n')
		if err != nil {
			return labelInput{}, err
		}
		botChoice = strings.TrimSpace(botChoice)
		switch botChoice {
		case "1":
			label.BotType = "scraper"
		case "2":
			label.BotType = "ddos"
		case "3":
			label.BotType = "crawler"
		case "4":
			label.BotType = "spam"
		case "5":
			label.BotType = "scanner"
		case "6":
			label.BotType = "other"
		default:
			label.BotType = "unknown"
		}
	}

	// Ask for confidence
	fmt.Print("\nHow confident are you? (1-5): ")
	confStr, err := reader.ReadString('\n')
	if err != nil {
		return labelInput{}, err
	}
	confStr = strings.TrimSpace(confStr)
	conf, err := strconv.Atoi(confStr)
	if err != nil || conf < 1 || conf > 5 {
		conf = 3 // Default to medium confidence
	}
	label.Confidence = conf

	// Optional notes
	fmt.Print("Notes (optional): ")
	notes, err := reader.ReadString('\n')
	if err != nil {
		return labelInput{}, err
	}
	label.Notes = strings.TrimSpace(notes)
	return label, nil
}

// loadDetections reads detections from a JSON array file, falling back to JSONL.
func loadDetections(filename string) ([]detectionInput, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Try to parse as JSON array first
	var detections []detectionInput
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&detections)
	if err == nil {
		return detections, nil
	}

	// If that fails, try JSONL (one JSON object per line)
	file.Seek(0, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var det detectionInput
		if err := json.Unmarshal(scanner.Bytes(), &det); err != nil {
			logrus.WithError(err).Warn("Failed to parse line")
			continue
		}
		detections = append(detections, det)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return detections, nil
}

// loadLabels reads previously written labels (JSONL) keyed by IP + timestamp.
func loadLabels(filename string) (map[string]LabeledDetection, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	labels := make(map[string]LabeledDetection)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var label LabeledDetection
		if err := json.Unmarshal(scanner.Bytes(), &label); err != nil {
			logrus.WithError(err).Warn("Failed to parse label")
			continue
		}
		key := label.IP + "_" + label.Timestamp.Format(time.RFC3339)
		labels[key] = label
	}
	return labels, scanner.Err()
}
