package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Simple Discord message structure
type DiscordMessage struct {
	Content string `json:"content"`
}

type SubnetTracker struct {
	sync.Mutex
	attempts  map[string]int  // subnet -> attempts in last minute
	blacklist map[string]bool // subnet -> is blacklisted
	lastReset time.Time       // last time attempts were reset
}

func NewTracker() *SubnetTracker {
	return &SubnetTracker{
		attempts:  make(map[string]int),
		blacklist: make(map[string]bool),
		lastReset: time.Now(),
	}
}

func setupLogging(logFile string) (*os.File, error) {
	// Open log file with append mode, create if not exists
	file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	// Configure log package to write to file and include timestamp
	log.SetOutput(file)
	log.SetFlags(log.Ldate | log.Ltime)

	return file, nil
}

func logEvent(file *os.File, format string, v ...interface{}) {
	// Get current timestamp
	timestamp := time.Now().Format("2006-01-02 15:04:05")

	// Format the message
	msg := fmt.Sprintf(format, v...)

	// Write to file with timestamp
	fmt.Fprintf(file, "[%s] %s\n", timestamp, msg)
}

func getSubnet(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ip
	}
	return strings.Join(parts[:3], ".") + ".0/24"
}

func getGeoIP(ip string) string {
	if ip == "" {
		return "Unknown"
	}

	resp, err := http.Get(fmt.Sprintf("http://ip-api.com/json/%s", ip))
	if err != nil {
		return "Unknown"
	}
	defer resp.Body.Close()

	var result struct {
		Country string `json:"country"`
		City    string `json:"city"`
		Status  string `json:"status"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "Unknown"
	}

	if result.Status != "success" {
		return "Unknown"
	}

	if result.City != "" && result.Country != "" {
		return fmt.Sprintf("%s, %s", result.City, result.Country)
	}
	return "Unknown"
}

func (t *SubnetTracker) isBlocked(subnet string) bool {
	t.Lock()
	defer t.Unlock()
	return t.blacklist[subnet]
}

func (t *SubnetTracker) trackAttempt(subnet string, webhookURL string, logFile *os.File) {
	t.Lock()
	defer t.Unlock()

	if t.blacklist[subnet] {
		return
	}

	t.attempts[subnet]++

	// If more than 5 attempts in a minute, blacklist the subnet
	if t.attempts[subnet] > 5 {
		t.blacklist[subnet] = true

		// Format block message
		msg := fmt.Sprintf("🚫 Subnet `%s` blocked > %d attempts in the last minute",
			subnet, t.attempts[subnet])

		fmt.Printf("🚫 Subnet %s blocked > %d attempts in the last minute\n",
			subnet, t.attempts[subnet])

		// Log the block
		logEvent(logFile, "Block: %s", msg)

		// Send to Discord
		webhook := DiscordMessage{Content: msg}
		jsonData, _ := json.Marshal(webhook)
		http.Post(webhookURL, "application/json", bytes.NewBuffer(jsonData))
	}
}

func (t *SubnetTracker) cleanup() {
	now := time.Now()
	if now.Sub(t.lastReset) < time.Minute {
		return
	}

	t.Lock()
	defer t.Unlock()

	// Reset attempt counts every minute
	t.attempts = make(map[string]int)
	t.lastReset = now
}

func extractIP(line string) string {
	// Try different patterns to extract IP
	patterns := []string{
		`from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`,
		`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+port`,
		`for\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`,
		`user.*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		if matches := re.FindStringSubmatch(line); len(matches) > 1 {
			return matches[1]
		}
	}
	return ""
}

func extractUsername(line string) string {
	patterns := []string{
		`for\s+user\s+(\w+)`,
		`user\s+(\w+)`,
		`for\s+(\w+)`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		if matches := re.FindStringSubmatch(line); len(matches) > 1 {
			return matches[1]
		}
	}
	return "unknown"
}

func main() {
	webhookURL := flag.String("webhook", "", "Discord webhook URL")
	logPath := flag.String("log", "ssh_monitor.log", "Path to log file")
	flag.Parse()

	if *webhookURL == "" {
		log.Fatal("Please provide a Discord webhook URL using -webhook flag")
	}

	// Setup logging
	logFile, err := setupLogging(*logPath)
	if err != nil {
		log.Fatal("Error setting up logging:", err)
	}
	defer logFile.Close()

	tracker := NewTracker()
	// Only show new logs with -n 0
	cmd := exec.Command("journalctl", "-f", "-n", "0", "-u", "ssh.service", "--no-pager")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatal("Error creating stdout pipe:", err)
	}

	if err := cmd.Start(); err != nil {
		log.Fatal("Error starting journalctl:", err)
	}

	scanner := bufio.NewScanner(stdout)
	startMsg := "🔒 SSH Monitor Started - Watching for suspicious activity..."
	log.Println(startMsg)
	logEvent(logFile, "%s", startMsg)

	// Send start message to Discord
	webhook := DiscordMessage{Content: startMsg}
	jsonData, _ := json.Marshal(webhook)
	http.Post(*webhookURL, "application/json", bytes.NewBuffer(jsonData))

	for scanner.Scan() {
		line := scanner.Text()

		// Log raw SSH line
		logEvent(logFile, "Raw: %s", line)

		// Look for any SSH-related activity
		if !strings.Contains(strings.ToLower(line), "ssh") {
			continue
		}

		ip := extractIP(line)
		if ip == "" {
			continue
		}

		subnet := getSubnet(ip)
		if !tracker.isBlocked(subnet) {
			// Get location
			location := getGeoIP(ip)
			username := extractUsername(line)

			var event string
			if strings.Contains(line, "Accepted") {
				// Successful login
				event = fmt.Sprintf("✅ Successful login from %s (%s) as '%s'",
					ip, location, username)
				fmt.Printf("✅ Successful login from %s (%s) as '%s'\n",
					ip, location, username)
			} else {
				// Other SSH activity
				event = fmt.Sprintf("🔍 SSH activity from %s (%s) Subnet: %s",
					ip, location, subnet)
				fmt.Printf("🔍 SSH activity from %s (%s) Subnet: %s\n",
					ip, location, subnet)
			}

			// Log the event
			logEvent(logFile, "Event: %s", event)

			// Send to Discord
			webhook := DiscordMessage{Content: event}
			jsonData, _ := json.Marshal(webhook)
			http.Post(*webhookURL, "application/json", bytes.NewBuffer(jsonData))

			// Only track failed attempts
			if !strings.Contains(line, "Accepted") {
				tracker.trackAttempt(subnet, *webhookURL, logFile)
			}
		} else {
			// Log blocked attempts too
			logEvent(logFile, "Blocked attempt from %s (subnet %s)", ip, subnet)
		}

		tracker.cleanup()
	}
}
