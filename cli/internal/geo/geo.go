/*
 * Copyright (c) 2026, Psiphon Inc.
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

// Package geo provides client geolocation via tcpdump and geoiplookup
package geo

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Result represents a country with its client count
type Result struct {
	Code    string `json:"code"`
	Country string `json:"country"`
	Count   int    `json:"count"`
}

// Collector continuously collects geo stats in the background
type Collector struct {
	mu       sync.RWMutex
	results  []Result
	interval time.Duration
	iface    string
	packets  int
	timeout  int
}

// NewCollector creates a new geo stats collector
func NewCollector(interval time.Duration) *Collector {
	return &Collector{
		interval: interval,
		iface:    "any",
		packets:  500,
		timeout:  30,
	}
}

// Start begins collecting geo stats in the background
func (c *Collector) Start(ctx context.Context) error {
	if err := CheckDependencies(); err != nil {
		return err
	}
	go c.run(ctx)
	return nil
}

func (c *Collector) run(ctx context.Context) {
	c.collect()
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.collect()
		}
	}
}

func (c *Collector) collect() {
	ips, err := CaptureIPs(c.iface, c.packets, c.timeout)
	if err != nil || len(ips) == 0 {
		return
	}

	results, err := LookupIPs(ips)
	if err != nil {
		return
	}

	c.mu.Lock()
	c.results = results
	c.mu.Unlock()
}

// GetResults returns the current geo stats
func (c *Collector) GetResults() []Result {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.results == nil {
		return []Result{}
	}
	out := make([]Result, len(c.results))
	for i, r := range c.results {
		out[i] = r
	}
	return out
}

// CheckDependencies verifies tcpdump and geoiplookup are installed
func CheckDependencies() error {
	if _, err := exec.LookPath("tcpdump"); err != nil {
		return fmt.Errorf("tcpdump not found (apt install tcpdump)")
	}
	if _, err := exec.LookPath("geoiplookup"); err != nil {
		return fmt.Errorf("geoiplookup not found (apt install geoip-bin)")
	}
	return nil
}

func CaptureIPs(iface string, packets, timeout int) ([]string, error) {
	cmd := exec.Command("timeout", fmt.Sprintf("%d", timeout), "tcpdump",
		"-ni", iface, "-c", fmt.Sprintf("%d", packets), "inbound and (tcp or udp)")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	ipSet := make(map[string]struct{})
	ipRegex := regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, " In ") {
			continue
		}
		if m := ipRegex.FindStringSubmatch(line); len(m) > 0 && !isPrivateIP(m[1]) {
			ipSet[m[1]] = struct{}{}
		}
	}
	cmd.Wait()

	ips := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		ips = append(ips, ip)
	}
	return ips, nil
}

func LookupIPs(ips []string) ([]Result, error) {
	counts := make(map[string]int)
	names := make(map[string]string)
	re := regexp.MustCompile(`GeoIP Country Edition: ([A-Z]{2}), (.+)`)

	for _, ip := range ips {
		out, err := exec.Command("geoiplookup", ip).Output()
		if err != nil {
			continue
		}
		if m := re.FindStringSubmatch(string(out)); len(m) == 3 {
			counts[m[1]]++
			names[m[1]] = normalizeCountry(m[2])
		}
	}

	results := make([]Result, 0, len(counts))
	for code, count := range counts {
		results = append(results, Result{Code: code, Country: names[code], Count: count})
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Count > results[j].Count })
	return results, nil
}

func isPrivateIP(ip string) bool {
	if strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "127.") {
		return true
	}
	if strings.HasPrefix(ip, "172.") {
		var b int
		fmt.Sscanf(ip, "172.%d.", &b)
		return b >= 16 && b <= 31
	}
	return false
}

func normalizeCountry(name string) string {
	mapping := map[string]string{
		"Iran, Islamic Republic of":                  "Iran",
		"Korea, Republic of":                         "South Korea",
		"Korea, Democratic People's Republic of":     "North Korea",
		"Russian Federation":                         "Russia",
		"United States":                              "USA",
		"United Kingdom":                             "UK",
		"United Arab Emirates":                       "UAE",
		"Viet Nam":                                   "Vietnam",
		"Taiwan, Province of China":                  "Taiwan",
		"Syrian Arab Republic":                       "Syria",
		"Venezuela, Bolivarian Republic of":          "Venezuela",
		"Tanzania, United Republic of":               "Tanzania",
		"Congo, The Democratic Republic of the":      "DR Congo",
		"Moldova, Republic of":                       "Moldova",
		"Palestine, State of":                        "Palestine",
		"Lao People's Democratic Republic":           "Laos",
		"Micronesia, Federated States of":            "Micronesia",
		"Macedonia, the Former Yugoslav Republic of": "North Macedonia",
		"Bolivia, Plurinational State of":            "Bolivia",
		"Brunei Darussalam":                          "Brunei",
	}
	if short, ok := mapping[name]; ok {
		return short
	}
	return name
}
