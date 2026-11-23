package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

func startTUI(shutdown chan struct{}) {
	go func() {
		<-shutdown
		fmt.Println("\n[TUI] shutdown")
	}()

	var mu sync.Mutex
	var inputActive bool
	var lastEvents int
	var rateHistory []int
	var screen int
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	go func() {
		for range ticker.C {
			mu.Lock()
			if inputActive {
				mu.Unlock()
				continue
			}
			mu.Unlock()
			mu.Lock()
			current := eventCount()
			rate := current - lastEvents
			lastEvents = current
			rateHistory = append(rateHistory, rate)
			if len(rateHistory) > 20 {
				rateHistory = rateHistory[len(rateHistory)-20:]
			}
			mu.Unlock()
			renderTUIScreenWithExtras(rateHistory, screen)
		}
	}()

	reader := bufio.NewReader(os.Stdin)
	for {
		mu.Lock()
		h := append([]int(nil), rateHistory...)
		mu.Unlock()
		renderTUIScreenWithExtras(h, screen)
		fmt.Print("\nTUI> ")
		mu.Lock()
		inputActive = true
		mu.Unlock()
		line, err := reader.ReadString('\n')
		mu.Lock()
		inputActive = false
		mu.Unlock()
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if handleTUICommand(reader, &screen, &mu, &inputActive, line) {
			return
		}
	}
}

func renderTUIScreenWithExtras(rateHistory []int, screen int) {
	fmt.Print("\x1b[2J\x1b[H")
	mode := Mode().String()
	trapsEnabled := 0
	trapsTotal := 0
	for _, t := range config.Traps {
		trapsTotal++
		if t.Enabled {
			trapsEnabled++
		}
	}
	ifaces := collectIfaces()
	attached := 0
	for _, i := range ifaces {
		if i.Mode != "" && i.Mode != "off" && i.Mode != "unknown" {
			attached++
		}
	}
	banMutex.Lock()
	localBans := len(banExpirations)
	banMutex.Unlock()
	logMutex.Lock()
	threatCount := len(eventLog)
	logMutex.Unlock()

	surfaceLocal := attached * trapsEnabled

	licenseState := licenseDisplayName()
	sharingState := "Off"
	if trustedNetworkSharingEnabled() {
		sharingState = "Enabled"
	}
	screenLabel := screenName(screen)

	fmt.Printf("HONEY MESH TUI %s | Mode: %s | License: %s | Trusted Mesh Networks: %s | Screen: %s\n",
		Version, colorMode(mode), licenseState, sharingState, screenLabel)
	fmt.Printf("Surface: %d  Traps: %d/%d  Ifaces: %d/%d  Blocks: %d  Threats: %d  Peers: %d  Events/s: %s\n",
		surfaceLocal, trapsEnabled, trapsTotal, attached, len(ifaces), localBans, threatCount, peerCountSafe(), sparkline(rateHistory))
	fmt.Printf("Keys: x=next  m=mode  t=trap  w=watchdog  b=banner  i=iface  j=join  r=revoke  l=license  c=csv  h=help  q=quit\n")
	fmt.Println(strings.Repeat("-", 120))

	if screen == 0 {
		fmt.Println("TRAPS (PORT / SERVICE / PROTO / STATUS / FLAGS)")
		printTrapsSingle()
		fmt.Println(strings.Repeat("-", 120))

		fmt.Println("INTERFACES (NAME / IP / STATE / MODE)")
		printIfaces()
	} else if screen == 1 {
		fmt.Println("ACTIVE BANS (IP / EXPIRES)")
		printBans()
		fmt.Println(strings.Repeat("-", 120))

		fmt.Println("MESH PEERS (PEER / LAST SEEN / AGE / STATUS)")
		printPeers()
		fmt.Println(strings.Repeat("-", 120))

		fmt.Println("LIVE THREAT STREAM (last 12)")
		printEvents(12)
	} else {
		fmt.Println("LIVE THREAT STREAM (last 20)")
		printEvents(20)
	}

	fmt.Println(strings.Repeat("-", 120))
	fmt.Printf("Status: %s | Dropped telemetry: %d | Dropped DB: %d\n",
		time.Now().Format("15:04:05"),
		droppedTelemetry.Load(),
		droppedDB.Load(),
	)
}

func printTrapsSingle() {
	snap := trapSnapshot()
	ports := make([]string, 0, len(snap))
	for p := range snap {
		ports = append(ports, p)
	}
	sortPorts(ports)
	for _, p := range ports {
		fmt.Println(formatTrapCompact(p, snap))
	}
}

func printIfaces() {
	fmt.Printf("%-12s %-26s %-6s %-8s\n", "NAME", "IP", "STATE", "MODE")
	for _, i := range collectIfaces() {
		fmt.Printf("%-12s %-26s %-6s %-8s\n", i.Name, truncate(i.IPs, 26), boolStr(i.IsUp, "up", "down"), i.Mode)
	}
}

func printBans() {
	banMutex.Lock()
	if len(banExpirations) == 0 {
		banMutex.Unlock()
		fmt.Println("none")
		return
	}
	type banRow struct {
		ip  string
		exp time.Time
	}
	rows := make([]banRow, 0, len(banExpirations))
	for ip, exp := range banExpirations {
		rows = append(rows, banRow{ip: ip, exp: exp})
	}
	banMutex.Unlock()
	sort.Slice(rows, func(i, j int) bool { return rows[i].exp.Before(rows[j].exp) })
	fmt.Printf("%-18s %-25s\n", "IP", "EXPIRES")
	for _, row := range rows {
		fmt.Printf("%-18s %-25s\n", row.ip, row.exp.Format(time.RFC3339))
	}
}

func printEvents(n int) {
	logMutex.Lock()
	defer logMutex.Unlock()
	start := 0
	if len(eventLog) > n {
		start = len(eventLog) - n
	}
	fmt.Printf("%-19s %-18s %-18s %-6s %-10s %-6s %-18s %-18s %-20s\n",
		"TIME", "SRC", "DST", "PORT", "TYPE", "IFACE", "JA4", "JA3", "PAYLOAD")
	printed := 0
	for _, e := range eventLog[start:] {
		if e.Timestamp == "" {
			continue
		}
		ja4 := truncate(e.JA4, 18)
		if label := ja4LabelFor(e.JA4); label != "" {
			ja4 = truncate(e.JA4, 10) + "•" + truncate(label, 7)
		}
		ja3 := truncate(e.JA3, 18)
		if label := ja3LabelFor(e.JA3); label != "" {
			ja3 = truncate(e.JA3, 10) + "•" + truncate(label, 7)
		}
		fmt.Printf("%-19s %-18s %-18s %-6s %-10s %-6s %-18s %-18s %-20s\n",
			truncate(e.Timestamp, 19),
			truncate(e.Attacker, 18),
			truncate(e.TargetIP, 18),
			truncate(e.Target, 6),
			truncate(e.Type, 10),
			truncate(e.Interface, 6),
			ja4,
			ja3,
			truncate(e.Payload, 20),
		)
		printed++
	}
	if printed == 0 {
		fmt.Println("no events")
	}
}

func printPeers() {
	if scp == nil {
		fmt.Println("mesh not running")
		return
	}
	stats := scp.PeerStats()
	if len(stats) == 0 {
		fmt.Println("no peers")
		return
	}
	fmt.Printf("%-24s %-20s %-8s %-8s\n", "PEER", "LAST SEEN", "AGE", "STATUS")
	now := time.Now()
	peers := make([]string, 0, len(stats))
	for p := range stats {
		peers = append(peers, p)
	}
	sortPortsLike(peers)
	for _, p := range peers {
		ts := stats[p]
		age := int(now.Sub(ts).Seconds())
		status := "stale"
		if age < 30 {
			status = "healthy"
		}
		fmt.Printf("%-24s %-20s %-8s %-8s\n", p, truncate(ts.Format(time.RFC3339), 20), fmt.Sprintf("%ds", age), colorPeerStatus(status))
	}
}

func handleTUICommand(reader *bufio.Reader, screen *int, mu *sync.Mutex, inputActive *bool, line string) bool {
	parts := splitArgs(line)
	if len(parts) == 0 {
		return false
	}
	switch strings.ToLower(parts[0]) {
	case "q", "quit", "exit":
		return true
	case "x":
		*screen = (*screen + 1) % 3
		return false
	case "e", "events", "tab", "screen":
		*screen = (*screen + 1) % 3
		return false
	case "h", "help":
		fmt.Println("\nCommands:")
		fmt.Println("  mode <test|enforce|lockdown>     Set enforcement mode.")
		fmt.Println("    example: mode enforce")
		fmt.Println("  trap <enable|disable|watchdog|banner> <port> [value]")
		fmt.Println("    enable/disable: toggle a trap on a port.")
		fmt.Println("    example: trap enable 22")
		fmt.Println("    watchdog: on/off for aggressive responses.")
		fmt.Println("    example: trap watchdog 80 on")
		fmt.Println("    banner: set banner text shown to clients.")
		fmt.Println("    example: trap banner 21 Unauthorized access")
		fmt.Println("  iface <attach|detach> <name>    Attach/detach an interface.")
		fmt.Println("    example: iface attach eth0")
		fmt.Println("  events                           Show events/bans screen.")
		fmt.Println("  x                                Cycle screens (main/ops/events).")
		fmt.Println("  license <path>                   Install a license JSON file.")
		fmt.Println("    example: license /etc/honeymesh/license.json")
		fmt.Println("  csv <path> [limit] [since] [until]")
		fmt.Println("    Export events to CSV. Timestamps are RFC3339.")
		fmt.Println("    example: csv /tmp/events.csv 200 2026-02-20T00:00:00Z 2026-02-23T23:59:59Z")
		fmt.Println("  meshjoin <peer:port> <token>     Join a mesh peer.")
		fmt.Println("    example: meshjoin 10.0.0.5:9443 abcdef123")
		fmt.Println("  meshrevoke <peer:port>           Revoke a mesh peer.")
		fmt.Println("    example: meshrevoke 10.0.0.5:9443")
		fmt.Println("  quit                             Exit the TUI.")
		pauseForEnter(reader, mu, inputActive)
		return false
	case "m":
		choice := prompt(reader, "Mode (test/enforce/lockdown)", mu, inputActive)
		if choice != "" {
			return handleTUICommand(reader, screen, mu, inputActive, "mode "+choice)
		}
		return false
	case "t":
		port := prompt(reader, "Trap port", mu, inputActive)
		if port == "" {
			return false
		}
		trap, ok := config.Traps[port]
		if !ok {
			return false
		}
		if trap.Enabled {
			return handleTUICommand(reader, screen, mu, inputActive, "trap disable "+port)
		}
		return handleTUICommand(reader, screen, mu, inputActive, "trap enable "+port)
	case "w":
		port := prompt(reader, "Watchdog port", mu, inputActive)
		if port == "" {
			return false
		}
		trap, ok := config.Traps[port]
		if !ok {
			return false
		}
		val := "on"
		if trap.Watchdog {
			val = "off"
		}
		return handleTUICommand(reader, screen, mu, inputActive, "trap watchdog "+port+" "+val)
	case "b":
		port := prompt(reader, "Banner port", mu, inputActive)
		if port == "" {
			return false
		}
		text := prompt(reader, "Banner text", mu, inputActive)
		if text == "" {
			return false
		}
		return handleTUICommand(reader, screen, mu, inputActive, "trap banner "+port+" "+text)
	case "i":
		name := prompt(reader, "Interface name", mu, inputActive)
		if name == "" {
			return false
		}
		mode := GetIfaceMode(name)
		if mode == IfaceOff || mode == "" {
			return handleTUICommand(reader, screen, mu, inputActive, "iface attach "+name)
		}
		return handleTUICommand(reader, screen, mu, inputActive, "iface detach "+name)
	case "j":
		peer := prompt(reader, "Peer IP:PORT", mu, inputActive)
		token := prompt(reader, "Join token", mu, inputActive)
		if peer == "" || token == "" {
			return false
		}
		return handleTUICommand(reader, screen, mu, inputActive, "meshjoin "+peer+" "+token)
	case "r":
		peer := prompt(reader, "Peer IP:PORT to revoke", mu, inputActive)
		if peer == "" {
			return false
		}
		return handleTUICommand(reader, screen, mu, inputActive, "meshrevoke "+peer)
	case "l":
		path := prompt(reader, "License file path", mu, inputActive)
		if path == "" {
			return false
		}
		return handleTUICommand(reader, screen, mu, inputActive, "license "+path)
	case "c":
		path := prompt(reader, "CSV output path", mu, inputActive)
		if path == "" {
			return false
		}
		return handleTUICommand(reader, screen, mu, inputActive, "csv "+path)
	case "mode":
		if len(parts) < 2 {
			return false
		}
		switch strings.ToLower(parts[1]) {
		case "test":
			if err := SetMode(ModeTest); err != nil {
				fmt.Printf("[MODE] reconciliation failed: %v\n", err)
			}
		case "enforce":
			if err := SetMode(ModeEnforce); err != nil {
				fmt.Printf("[MODE] reconciliation failed: %v\n", err)
			}
		case "lockdown":
			if err := SetMode(ModeLockdown); err != nil {
				fmt.Printf("[MODE] reconciliation failed: %v\n", err)
			}
		}
	case "trap":
		if len(parts) < 3 {
			return false
		}
		port := parts[2]
		trap, ok := config.Traps[port]
		if !ok {
			return false
		}
		switch strings.ToLower(parts[1]) {
		case "enable":
			trap.Enabled = true
			if strings.ToLower(trap.Proto) == "udp" {
				go startUDPTrap(port, trap)
			} else {
				go startSingleTrap(port, trap)
			}
		case "disable":
			trap.Enabled = false
			stopTrap(trap)
		case "watchdog":
			if len(parts) < 4 {
				return false
			}
			trap.Watchdog = strings.ToLower(parts[3]) == "on"
		case "banner":
			if len(parts) < 4 {
				return false
			}
			trap.Banner = strings.Join(parts[3:], " ")
		}
		saveConfig()
	case "iface":
		if len(parts) < 3 {
			return false
		}
		name := parts[2]
		switch strings.ToLower(parts[1]) {
		case "attach":
			if err := applyInterfaceMode(name, IfaceEnforce); err != nil {
				fmt.Printf("interface attach error: %v\n", err)
			} else if err := persistInterfaceSelection(name, true); err != nil {
				fmt.Printf("interface state error: %v\n", err)
			}
		case "detach":
			if err := applyInterfaceMode(name, IfaceOff); err != nil {
				fmt.Printf("interface detach error: %v\n", err)
			} else if err := persistInterfaceSelection(name, false); err != nil {
				fmt.Printf("interface state error: %v\n", err)
			}
		}
	case "license":
		if len(parts) < 2 {
			return false
		}
		if err := installLicense(parts[1]); err != nil {
			fmt.Printf("license error: %v\n", err)
			time.Sleep(2 * time.Second)
		}
	case "csv":
		if len(parts) < 2 {
			return false
		}
		limit := 5000
		var since, until string
		if len(parts) >= 3 {
			if n, err := strconv.Atoi(parts[2]); err == nil {
				limit = n
			}
		}
		if len(parts) >= 4 {
			since = parts[3]
		}
		if len(parts) >= 5 {
			until = parts[4]
		}
		if err := exportCSV(parts[1], limit, since, until); err != nil {
			fmt.Printf("csv error: %v\n", err)
			time.Sleep(2 * time.Second)
		}
	case "meshjoin":
		if len(parts) < 3 {
			return false
		}
		if scp == nil {
			fmt.Println("mesh not running")
			time.Sleep(2 * time.Second)
			return false
		}
		if max := meshMaxNodesAllowed(); max > 0 && !activeMeshPeerConfigured(parts[1]) && 1+meshPeerCount() >= max {
			fmt.Printf("mesh join blocked: direct peer limit reached (%d)\n", max-1)
			time.Sleep(2 * time.Second)
			return false
		}
		addr := fmt.Sprintf("%s:%s", config.BindIP, config.MeshPort)
		if err := scp.Join(parts[1], parts[2], addr); err != nil {
			fmt.Printf("join error: %v\n", err)
			time.Sleep(2 * time.Second)
			return false
		}
		addPeer(parts[1])
	case "meshrevoke":
		if len(parts) < 2 {
			return false
		}
		if err := revokeMeshPeer(parts[1]); err != nil {
			fmt.Printf("revoke error: %v\n", err)
		}
	}
	return false
}

func installLicense(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !json.Valid(data) {
		return fmt.Errorf("invalid json")
	}
	return os.WriteFile("license.json", data, 0600)
}

func exportCSV(path string, limit int, sinceStr, untilStr string) error {
	var since, until time.Time
	var hasSince, hasUntil bool
	if sinceStr != "" {
		t, err := time.Parse(time.RFC3339, sinceStr)
		if err != nil {
			return err
		}
		since = t
		hasSince = true
	}
	if untilStr != "" {
		t, err := time.Parse(time.RFC3339, untilStr)
		if err != nil {
			return err
		}
		until = t
		hasUntil = true
	}

	rows := snapshotEvents(0)

	filtered := make([]Event, 0, len(rows))
	for _, e := range rows {
		if hasSince || hasUntil {
			ts, err := time.Parse(time.RFC3339, e.Timestamp)
			if err != nil {
				continue
			}
			if hasSince && ts.Before(since) {
				continue
			}
			if hasUntil && ts.After(until) {
				continue
			}
		}
		filtered = append(filtered, e)
	}
	if limit > 0 && len(filtered) > limit {
		filtered = filtered[len(filtered)-limit:]
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	_, _ = f.WriteString("DATE,TIME,ACTION,SRC_IP,DST_IP,DST_PORT,SERVICE,NODE,INTERFACE,JA4,JA3,BAN_SOURCE,DETAILS,PAYLOAD\n")
	for _, e := range filtered {
		action := e.Type
		details := ""
		if label := ja4LabelFor(e.JA4); label != "" {
			details = "ja4_label=" + label
		}
		if label := ja3LabelFor(e.JA3); label != "" {
			if details == "" {
				details = "ja3_legacy_label=" + label
			} else {
				details = details + " ja3_legacy_label=" + label
			}
		}
		if e.Interface != "" {
			if details == "" {
				details = "iface=" + e.Interface
			} else {
				details = details + " iface=" + e.Interface
			}
		}
		if e.Entropy > 0 {
			if details == "" {
				details = fmt.Sprintf("entropy=%.2f", e.Entropy)
			} else {
				details = details + fmt.Sprintf(" entropy=%.2f", e.Entropy)
			}
		}
		dateStr := ""
		timeStr := ""
		if ts, err := time.Parse(time.RFC3339, e.Timestamp); err == nil {
			dateStr = ts.Format("2006-01-02")
			timeStr = ts.Format("15:04:05-07:00")
		}
		payloadOut := e.Payload
		if e.Interface == "xdp" && strings.HasPrefix(e.Payload, "action=") {
			if details == "" {
				details = e.Payload
			} else {
				details = details + " " + e.Payload
			}
			payloadOut = ""
		}
		banSource := banSourceForIP(e.Attacker)
		line := fmt.Sprintf("%q,%q,%q,%q,%q,%q,%q,%q,%q,%q,%q,%q,%q,%q\n",
			dateStr, timeStr, action, e.Attacker, e.TargetIP, e.Target, e.Service, e.Node, e.Interface, e.JA4, e.JA3, banSource, details, payloadOut)
		_, _ = f.WriteString(line)
	}
	return nil
}

func splitArgs(s string) []string {
	return strings.Fields(s)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

func boolStr(v bool, t, f string) string {
	if v {
		return t
	}
	return f
}

func trapServiceName(port string) string {
	switch port {
	case "21":
		return "FTP"
	case "22":
		return "SSH"
	case "23":
		return "TELNET"
	case "25":
		return "SMTP"
	case "53":
		return "DNS"
	case "80":
		return "HTTP"
	case "110":
		return "POP3"
	case "143":
		return "IMAP"
	case "443":
		return "HTTPS"
	case "445":
		return "SMB"
	case "3306":
		return "MYSQL"
	case "3389":
		return "RDP"
	case "5432":
		return "POSTGRES"
	case "6379":
		return "REDIS"
	case "8080":
		return "HTTP-ALT"
	case "9200":
		return "ELASTIC"
	default:
		return "CUSTOM"
	}
}

func sortPorts(ports []string) {
	sort.Slice(ports, func(i, j int) bool {
		pi, _ := strconv.Atoi(ports[i])
		pj, _ := strconv.Atoi(ports[j])
		return pi < pj
	})
}

func formatTrapCompact(port string, snap map[string]trapView) string {
	t := snap[port]
	status := strings.ToUpper(t.Status)
	if t.Watchdog {
		status = "WATCHDOG"
	}
	flags := "-"
	if t.Enabled && t.Watchdog {
		flags = "E+W"
	} else if t.Enabled {
		flags = "EN"
	} else if t.Watchdog {
		flags = "WD"
	}
	return fmt.Sprintf(":%-4s  %-10s  %-4s  %-9s  %s",
		port,
		trapServiceName(port),
		t.Proto,
		flags,
		colorTrapStatus(status),
	)
}

func sortPortsLike(items []string) {
	sort.Strings(items)
}

func prompt(reader *bufio.Reader, label string, mu *sync.Mutex, inputActive *bool) string {
	mu.Lock()
	*inputActive = true
	mu.Unlock()
	fmt.Printf("%s: ", label)
	text, _ := reader.ReadString('\n')
	mu.Lock()
	*inputActive = false
	mu.Unlock()
	return strings.TrimSpace(text)
}

func pauseForEnter(reader *bufio.Reader, mu *sync.Mutex, inputActive *bool) {
	mu.Lock()
	*inputActive = true
	mu.Unlock()
	fmt.Print("\nPress Enter to continue...")
	reader.ReadString('\n')
	mu.Lock()
	*inputActive = false
	mu.Unlock()
}

func colorMode(mode string) string {
	switch mode {
	case "TEST":
		return "\x1b[34mTEST\x1b[0m"
	case "ENFORCE":
		return "\x1b[33mENFORCE\x1b[0m"
	case "LOCKDOWN":
		return "\x1b[31mLOCKDOWN\x1b[0m"
	default:
		return mode
	}
}

func colorTrapStatus(status string) string {
	switch strings.ToLower(status) {
	case "listening":
		return "\x1b[32mlistening\x1b[0m"
	case "watchdog":
		return "\x1b[38;5;208mwatchdog\x1b[0m"
	case "error":
		return "\x1b[31merror\x1b[0m"
	default:
		return status
	}
}

func colorPeerStatus(status string) string {
	switch status {
	case "healthy":
		return "\x1b[32mhealthy\x1b[0m"
	case "stale":
		return "\x1b[31mstale\x1b[0m"
	default:
		return status
	}
}

func sparkline(vals []int) string {
	if len(vals) == 0 {
		return "-"
	}
	blocks := []rune("▁▂▃▄▅▆▇█")
	max := 1
	for _, v := range vals {
		if v > max {
			max = v
		}
	}
	var b strings.Builder
	for _, v := range vals {
		idx := int(float64(v) / float64(max) * float64(len(blocks)-1))
		b.WriteRune(blocks[idx])
	}
	return b.String()
}

func screenName(screen int) string {
	switch screen {
	case 0:
		return "MAIN"
	case 1:
		return "OPS"
	default:
		return "EVENTS"
	}
}

func peerCountSafe() int {
	if scp == nil {
		return 0
	}
	return scp.PeerCount()
}
