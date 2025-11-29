package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"goscope/analyse_ai"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Структуры для AI результатов
type AIResult struct {
	URL       string
	RiskLevel int
	RiskStr   string
	Verdict   string
}

type AIRiskJSON struct {
	ID     int    `json:"id"`
	Risk   string `json:"risk"`
	Reason string `json:"reason"`
}

func main() {
	reader := bufio.NewReader(os.Stdin)

	// Чтение Groq API Key из аргументов или ENV
	groqKey := ""
	for i, arg := range os.Args {
		if arg == "--groq-key" && i+1 < len(os.Args) {
			groqKey = os.Args[i+1]
		}
	}
	if groqKey == "" {
		groqKey = os.Getenv("GROQ_API_KEY")
	}

	fmt.Print("Mode [scan/headless/combo] (default scan): ")
	modeStr, _ := reader.ReadString('\n')
	mode := strings.ToLower(strings.TrimSpace(modeStr))
	if mode == "" {
		mode = "scan"
	}

	if mode == "headless" || mode == "combo" {
		fmt.Println("\n" + strings.Repeat("⚠", 30))
		fmt.Println("⚠️  WARNING: Headless mode uses significant resources")
		fmt.Println("⚠️  - RAM: ~150-300MB per browser instance")
		fmt.Println("⚠️  - CPU: High load during page rendering")
		fmt.Println("⚠️  - Time: ~2-5 seconds per page")
		if mode == "combo" {
			fmt.Println("⚠️  - COMBO: Will run BOTH scan + headless sequentially")
		}
		fmt.Println(strings.Repeat("⚠", 30))

		fmt.Print("\nContinue? (y/n): ")
		confirm, _ := reader.ReadString('\n')
		if strings.ToLower(strings.TrimSpace(confirm)) != "y" {
			fmt.Println("Aborted.")
			return
		}
	}

	switch mode {
	case "headless":
		runHeadlessMode(reader, groqKey)
	case "combo":
		runComboMode(reader, groqKey)
	default:
		runScanMode(reader, groqKey)
	}
}

func runScanMode(reader *bufio.Reader, groqKey string) {
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("GoScope - Advanced Web Scanner")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()

	fmt.Print("Target URL: ")
	targetURL, _ := reader.ReadString('\n')
	targetURL = strings.TrimSpace(targetURL)

	if targetURL == "" {
		fmt.Println("❌ URL required!")
		return
	}

	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
	}
	if strings.HasPrefix(targetURL, "http://") {
		targetURL = strings.Replace(targetURL, "http://", "https://", 1)
	}

	fmt.Print("Concurrency (default 50): ")
	threadsStr, _ := reader.ReadString('\n')
	threadsStr = strings.TrimSpace(threadsStr)

	threads := 50
	if threadsStr != "" {
		if t, err := strconv.Atoi(threadsStr); err == nil && t > 0 {
			threads = t
		}
	}

	fmt.Print("Rate limit (ms between requests, default 0): ")
	rateStr, _ := reader.ReadString('\n')
	rateLimitMs := 0
	if r, err := strconv.Atoi(strings.TrimSpace(rateStr)); err == nil && r >= 0 {
		rateLimitMs = r
	}

	fmt.Print("Enable random User-Agent? (y/n, default n): ")
	uaStr, _ := reader.ReadString('\n')
	randomUA := strings.ToLower(strings.TrimSpace(uaStr)) == "y"

	fmt.Print("Enable SPA route detection? (y/n, default y): ")
	spaDetect, _ := reader.ReadString('\n')
	enableSPA := strings.ToLower(strings.TrimSpace(spaDetect)) != "n"

	fmt.Print("Verbose mode? (y/n, default n): ")
	verboseStr, _ := reader.ReadString('\n')
	verbose := strings.ToLower(strings.TrimSpace(verboseStr)) == "y"

	fmt.Print("Enable BFS auto-crawl? (y/n, default n): ")
	bfsStr, _ := reader.ReadString('\n')
	enableBFS := strings.ToLower(strings.TrimSpace(bfsStr)) == "y"

	bfsDepth := 0
	bfsMaxURLs := 0
	if enableBFS {
		fmt.Print("BFS max depth (default 2): ")
		depthStr, _ := reader.ReadString('\n')
		depthStr = strings.TrimSpace(depthStr)
		if depthStr != "" {
			if d, err := strconv.Atoi(depthStr); err == nil && d > 0 {
				bfsDepth = d
			} else {
				bfsDepth = 2
			}
		} else {
			bfsDepth = 2
		}

		fmt.Print("BFS max URLs to visit (default 100): ")
		maxStr, _ := reader.ReadString('\n')
		maxStr = strings.TrimSpace(maxStr)
		if maxStr != "" {
			if m, err := strconv.Atoi(maxStr); err == nil && m > 0 {
				bfsMaxURLs = m
			} else {
				bfsMaxURLs = 100
			}
		} else {
			bfsMaxURLs = 100
		}
	}

	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("🎯 Target: %s\n", targetURL)
	fmt.Printf("⚡ Threads: %d\n", threads)
	fmt.Printf("⏱️  RateLimit ms: %dms\n", rateLimitMs)
	fmt.Printf("🔍 SPA Detection: %v\n", enableSPA)
	fmt.Printf("📝 Verbose: %v\n", verbose)
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()

	scanner := NewScanner(targetURL, threads, enableSPA, verbose, rateLimitMs, randomUA)

	results, err := scanner.Scan()

	if err != nil {
		fmt.Printf("❌ Error: %v\n", err)
		return
	}

	displayResults(results, scanner, enableSPA)

	if enableBFS {
		results = runBFS(scanner, targetURL, results, bfsDepth, bfsMaxURLs, rateLimitMs)
	}

	// === AI INTEGRATION ===
	var finalAIResults []Result
	finalAIResults = append(finalAIResults, results...)

	for _, route := range scanner.spaRoutes {
		fullURL := route
		if !strings.HasPrefix(route, "http") {
			fullURL = scanner.BaseURL + route
		}
		isDup := false
		for _, r := range finalAIResults {
			if r.URL == fullURL {
				isDup = true
				break
			}
		}
		if !isDup {
			finalAIResults = append(finalAIResults, Result{
				URL:         fullURL,
				StatusCode:  0,
				ContextData: "Source: SPA Analysis (Not visited)",
			})
		}
	}

	runAIAnalysis(reader, finalAIResults, groqKey)
	// ======================

	saveResultsWithDedup(reader, results, scanner, enableSPA)
}

func runHeadlessMode(reader *bufio.Reader, groqKey string) {
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("GoScope - Headless Browser Mode")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()

	fmt.Print("Target URL: ")
	targetURL, _ := reader.ReadString('\n')
	targetURL = strings.TrimSpace(targetURL)

	if targetURL == "" {
		fmt.Println("❌ URL required!")
		return
	}

	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
	}

	fmt.Print("Max pages to crawl (default 50): ")
	maxPagesStr, _ := reader.ReadString('\n')
	maxPages := 50
	if p, err := strconv.Atoi(strings.TrimSpace(maxPagesStr)); err == nil && p > 0 {
		maxPages = p
	}

	fmt.Print("Enable deep mode (XHR/fetch capture)? (y/n, default y): ")
	deepStr, _ := reader.ReadString('\n')
	enableDeep := strings.ToLower(strings.TrimSpace(deepStr)) != "n"

	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("🎯 Target: %s\n", targetURL)
	fmt.Printf("📄 Max Pages: %d\n", maxPages)
	fmt.Printf("🔍 Deep Mode: %v\n", enableDeep)
	fmt.Println(strings.Repeat("=", 60))

	scanner := NewHeadlessScanner(targetURL, maxPages, enableDeep)
	results, err := scanner.Scan()

	if err != nil {
		fmt.Printf("❌ Error: %v\n", err)
		return
	}

	allURLs := scanner.GetAllURLs(results)

	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("✅ Found: %d unique URLs\n", len(allURLs))
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()

	for i, url := range allURLs {
		if i < 50 {
			fmt.Printf("  → %s\n", url)
		}
	}

	if len(allURLs) > 50 {
		fmt.Printf("\n... and %d more URLs\n", len(allURLs)-50)
	}

	// === AI INTEGRATION (Headless) ===
	var headlessResults []Result
	for _, u := range allURLs {
		headlessResults = append(headlessResults, Result{
			URL:         u,
			StatusCode:  200,
			ContextData: "Source: Headless Browser",
		})
	}
	runAIAnalysis(reader, headlessResults, groqKey)
	// ======================

	saveURLsWithDedup(reader, allURLs)
}

func runComboMode(reader *bufio.Reader, groqKey string) {
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("GoScope - COMBO Mode (Scan + Headless)")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()

	fmt.Print("Target URL: ")
	targetURL, _ := reader.ReadString('\n')
	targetURL = strings.TrimSpace(targetURL)

	if targetURL == "" {
		fmt.Println("❌ URL required!")
		return
	}

	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
	}
	if strings.HasPrefix(targetURL, "http://") {
		targetURL = strings.Replace(targetURL, "http://", "https://", 1)
	}

	fmt.Print("Concurrency for scan (default 50): ")
	threadsStr, _ := reader.ReadString('\n')
	threads := 50
	if t, err := strconv.Atoi(strings.TrimSpace(threadsStr)); err == nil && t > 0 {
		threads = t
	}

	fmt.Print("Max pages for headless (default 30): ")
	maxPagesStr, _ := reader.ReadString('\n')
	maxPages := 30
	if p, err := strconv.Atoi(strings.TrimSpace(maxPagesStr)); err == nil && p > 0 {
		maxPages = p
	}

	fmt.Print("Rate limit (ms between requests, default 0): ")
	rateStr, _ := reader.ReadString('\n')
	rateLimitMs := 0
	if r, err := strconv.Atoi(strings.TrimSpace(rateStr)); err == nil && r >= 0 {
		rateLimitMs = r
	}

	fmt.Print("Enable random User-Agent? (y/n, default n): ")
	uaStr, _ := reader.ReadString('\n')
	randomUA := strings.ToLower(strings.TrimSpace(uaStr)) == "y"

	fmt.Print("Enable SPA route detection? (y/n, default y): ")
	spaDetect, _ := reader.ReadString('\n')
	enableSPA := strings.ToLower(strings.TrimSpace(spaDetect)) != "n"

	fmt.Print("Verbose mode? (y/n, default n): ")
	verboseStr, _ := reader.ReadString('\n')
	verbose := strings.ToLower(strings.TrimSpace(verboseStr)) == "y"

	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("🎯 Target: %s\n", targetURL)
	fmt.Printf("⚡ Scan Threads: %d\n", threads)
	fmt.Printf("🌐 Headless Max Pages: %d\n", maxPages)
	fmt.Println(strings.Repeat("=", 60))

	// Этап 1: Обычный scan
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("📡 STAGE 1/2: Fast HTTP Scan")
	fmt.Println(strings.Repeat("=", 60))

	scanner := NewScanner(targetURL, threads, enableSPA, verbose, rateLimitMs, randomUA)

	scanResults, err := scanner.Scan()
	if err != nil {
		fmt.Printf("❌ Scan error: %v\n", err)
		return
	}

	fmt.Printf("\n✅ Stage 1 complete: %d URLs found\n", len(scanResults))

	// Этап 2: Headless
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("🌐 STAGE 2/2: Headless Browser Scan")
	fmt.Println(strings.Repeat("=", 60))

	headlessScanner := NewHeadlessScanner(targetURL, maxPages, true)
	headlessResults, err := headlessScanner.Scan()
	if err != nil {
		fmt.Printf("❌ Headless error: %v\n", err)
		return
	}

	headlessURLs := headlessScanner.GetAllURLs(headlessResults)
	fmt.Printf("\n✅ Stage 2 complete: %d URLs found\n", len(headlessURLs))

	// Объединение
	opts := DefaultNormalizeOptions()
	allURLs := make(map[string]bool)

	for _, r := range scanResults {
		canonical := CanonicalizeURL(r.URL, opts)
		allURLs[canonical] = true
	}

	for _, route := range scanner.spaRoutes {
		canonical := CanonicalizeURL(route, opts)
		allURLs[canonical] = true
	}
	headlessNew := 0
	for _, url := range headlessURLs {
		canonical := CanonicalizeURL(url, opts)
		if !allURLs[canonical] {
			allURLs[canonical] = true
			headlessNew++
		}
	}

	// Собираем финальный список
	finalURLs := []string{}
	for canonical := range allURLs {
		finalURLs = append(finalURLs, canonical)
	}

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("📊 COMBO RESULTS")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("✅ Total unique URLs: %d\n", len(finalURLs))
	fmt.Printf("   └─ From scan: %d\n", len(scanResults)+len(scanner.spaRoutes))
	fmt.Printf("   └─ New from headless: %d\n", headlessNew)
	fmt.Println(strings.Repeat("=", 60))

	// === AI INTEGRATION (FULL) ===
	var finalAIResults []Result
	finalAIResults = append(finalAIResults, scanResults...)

	for _, route := range scanner.spaRoutes {
		fullURL := route
		if !strings.HasPrefix(route, "http") {
			fullURL = scanner.BaseURL + route
		}
		isDup := false
		for _, r := range finalAIResults {
			if r.URL == fullURL {
				isDup = true
				break
			}
		}
		if !isDup {
			finalAIResults = append(finalAIResults, Result{
				URL:         fullURL,
				StatusCode:  0,
				ContextData: "Source: SPA Analysis (Not visited)",
			})
		}
	}
	for _, url := range headlessURLs {
		isDup := false
		for _, r := range finalAIResults {
			if r.URL == url {
				isDup = true
				break
			}
		}
		if !isDup {
			finalAIResults = append(finalAIResults, Result{
				URL:         url,
				StatusCode:  200,
				ContextData: "Source: Headless Browser",
			})
		}
	}

	runAIAnalysis(reader, finalAIResults, groqKey)
	// ======================

	saveURLsWithDedup(reader, finalURLs)
}

func displayResults(results []Result, scanner *Scanner, enableSPA bool) {
	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("✅ Scan complete! Found: %d URLs\n", len(results))
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()

	if len(results) == 0 {
		fmt.Println("Nothing found.")
	} else {
		byStatus := make(map[int][]Result)
		for _, r := range results {
			byStatus[r.StatusCode] = append(byStatus[r.StatusCode], r)
		}

		statuses := []int{200, 301, 302, 401, 403, 405, 500}
		for _, status := range statuses {
			if urls, ok := byStatus[status]; ok && len(urls) > 0 {
				fmt.Printf("\n[%d] Found: %d\n", status, len(urls))
				for _, r := range urls {
					note := ""
					if r.IsSPARoute {
						note = " [SPA Route]"
					}
					fmt.Printf("  → %s%s\n", r.URL, note)
				}
			}
		}
	}

	if enableSPA && len(scanner.spaRoutes) > 0 {
		fmt.Println("\n" + strings.Repeat("=", 60))
		fmt.Println("📝 Extracted SPA routes by type")
		fmt.Println(strings.Repeat("=", 60))

		pages := []string{}
		apis := []string{}
		unknown := []string{}

		for _, route := range scanner.spaRoutes {
			routeType := classifyRoute(route)
			switch routeType {
			case "page":
				pages = append(pages, route)
			case "api":
				apis = append(apis, route)
			default:
				unknown = append(unknown, route)
			}
		}

		if len(pages) > 0 {
			fmt.Printf("\n🌐 Pages (%d) - open in browser:\n", len(pages))
			for _, route := range pages {
				fmt.Printf("  • %s\n", route)
			}
		}
		// ... (остальные выводы можно оставить или убрать, для краткости)
	}
}

func runBFS(scanner *Scanner, targetURL string, results []Result, bfsDepth, bfsMaxURLs, rateLimitMs int) []Result {
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("🔄 Starting BFS auto-crawl")
	fmt.Println(strings.Repeat("=", 60))

	crawler := NewBFSCrawler(scanner, CrawlConfig{
		MaxDepth:  bfsDepth,
		RateLimit: time.Millisecond * time.Duration(rateLimitMs),
		MaxURLs:   bfsMaxURLs,
	})

	seedURLs := []string{targetURL}
	existingURLs := make(map[string]bool)

	for _, r := range results {
		existingURLs[r.URL] = true
	}

	for _, route := range scanner.spaRoutes {
		fullURL := scanner.BaseURL + route
		existingURLs[fullURL] = true
		seedURLs = append(seedURLs, fullURL)
	}

	bfsResults, err := crawler.CrawlMultiple(seedURLs)
	if err != nil {
		fmt.Printf("\n⚠️  BFS crawl error: %v\n", err)
	} else {
		newCount := 0
		for _, r := range bfsResults {
			if !existingURLs[r.URL] {
				results = append(results, r)
				newCount++
			}
		}
		fmt.Printf("\n✅ BFS discovered %d NEW URLs\n", newCount)
	}
	return results
}

func saveResultsWithDedup(reader *bufio.Reader, results []Result, scanner *Scanner, enableSPA bool) {
	fmt.Print("\n💾 Save results? (y/n): ")
	save, _ := reader.ReadString('\n')
	if strings.ToLower(strings.TrimSpace(save)) != "y" {
		fmt.Println("\n✨ Done!")
		return
	}
	// ... (код сохранения как у тебя) ...
	fmt.Println("✅ Results saved.")
}

func saveURLsWithDedup(reader *bufio.Reader, urls []string) {
	fmt.Print("\n💾 Save results? (y/n): ")
	save, _ := reader.ReadString('\n')
	if strings.ToLower(strings.TrimSpace(save)) != "y" {
		return
	}
	// ... (код сохранения) ...
	fmt.Println("✅ Results saved.")
}

func classifyRoute(path string) string {
	apiPatterns := []string{"/api/", "/graphql", "/auth/"}
	for _, p := range apiPatterns {
		if strings.HasPrefix(path, p) {
			return "api"
		}
	}
	return "page"
}

// ===============================================
// AI ANALYSIS LOGIC (GROQ VERSION)
// ===============================================

func getPriorityScore(r Result) int {
	score := 0
	if r.StatusCode >= 500 {
		score += 10
	}
	if r.StatusCode == 403 || r.StatusCode == 401 {
		score += 8
	}
	if strings.Contains(r.URL, "admin") || strings.Contains(r.URL, "api") {
		score += 5
	}
	return score
}

func runAIAnalysis(reader *bufio.Reader, results []Result, apiKey string) {
	if apiKey == "" {
		fmt.Print("🔑 Enter Groq API Key (leave empty to skip AI): ")
		keyInput, _ := reader.ReadString('\n')
		apiKey = strings.TrimSpace(keyInput)
		if apiKey == "" {
			fmt.Println("Skipping AI analysis (no key provided).")
			return
		}
	}

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("🧠 AI ANALYSIS STARTED (Groq Cloud API)")
	fmt.Println(strings.Repeat("=", 60))

	client := analyse_ai.NewClient(apiKey)

	// 1. Сортировка
	sort.Slice(results, func(i, j int) bool {
		return getPriorityScore(results[i]) > getPriorityScore(results[j])
	})

	// 2. Фильтрация
	var cleanResults []Result
	for _, r := range results {
		if strings.HasSuffix(r.URL, ".png") || strings.HasSuffix(r.URL, ".jpg") ||
			strings.HasSuffix(r.URL, ".css") || strings.HasSuffix(r.URL, ".ico") ||
			strings.HasSuffix(r.URL, ".woff") || strings.HasSuffix(r.URL, ".svg") {
			continue
		}
		cleanResults = append(cleanResults, r)
	}

	if len(cleanResults) > 50 {
		fmt.Printf("⚠️  Analysing top 50 of %d URLs...\n", len(cleanResults))
		cleanResults = cleanResults[:50]
	}

	var aiResults []AIResult
	batchSize := 5
	startTime := time.Now()

	for i := 0; i < len(cleanResults); i += batchSize {
		end := i + batchSize
		if end > len(cleanResults) {
			end = len(cleanResults)
		}
		batch := cleanResults[i:end]

		fmt.Printf("\n🔄 Processing batch %d-%d/%d...\n", i+1, end, len(cleanResults))

		var promptBuilder strings.Builder
		promptBuilder.WriteString("Analyze these HTTP endpoints for security risks.\n")

		for idx, r := range batch {
			ctxData := "No context"
			if r.ContextData != "" {
				if len(r.ContextData) > 300 {
					ctxData = r.ContextData[:300] + "..."
				} else {
					ctxData = r.ContextData
				}
			}
			promptBuilder.WriteString(fmt.Sprintf("--- ID %d ---\nURL: %s\nCode: %d\nContext: %s\n\n", idx+1, r.URL, r.StatusCode, ctxData))
		}

		promptBuilder.WriteString(`
### SYSTEM ROLE
You are a Security Analyst. Analyze HTTP endpoints based on the provided Context.
Do NOT hallucinate vulnerabilities. If Context is missing or unclear, mark as MANUAL_CHECK.

### RISK CATEGORIES
1. **CRITICAL**
   - Context EXPLICITLY contains: "AWS_ACCESS_KEY", "BEGIN RSA PRIVATE KEY", "root:x:0:0", or SQL syntax errors.
2. **HIGH**
   - Admin Panels (Status 200) with "Dashboard" or "Admin" in content.
   - Directory Listing ("Index of /").
3. **MEDIUM**
   - 500 Internal Server Errors.
   - Potential IDOR (numeric IDs in URL).
   - API endpoints returning sensitive user lists (PII).
4. **LOW**
   - Public pages (/login, /register, /home).
   - Static files (.js, .css, .png) without secrets.
   - 403/401/404 Status codes.
5. **MANUAL_CHECK**
   - If Context is "Source: SPA Analysis" and URL is ambiguous.

### OUTPUT FORMAT
Return ONLY a JSON array.
[{"id": <int>, "risk": "<Low/Medium/High/Critical/Manual>", "reason": "<Short specific reason>"}]
`)

		analysis, err := client.Analyze(promptBuilder.String())
		if err != nil {
			fmt.Printf("❌ Batch Error: %v\n", err)
			continue
		}

		cleanJSON := strings.TrimSpace(analysis)
		if idx := strings.Index(cleanJSON, "["); idx != -1 {
			cleanJSON = cleanJSON[idx:]
		}
		if idx := strings.LastIndex(cleanJSON, "]"); idx != -1 {
			cleanJSON = cleanJSON[:idx+1]
		}

		var jsonResp []AIRiskJSON
		err = json.Unmarshal([]byte(cleanJSON), &jsonResp)

		if err == nil && len(jsonResp) > 0 {
			fmt.Println("✅ JSON Parsed successfully")
			resultsMap := make(map[int]AIRiskJSON)
			for _, item := range jsonResp {
				resultsMap[item.ID] = item
			}

			for idx, r := range batch {
				item, exists := resultsMap[idx+1]
				riskLvl := 1
				riskStr := "Low"
				verdict := "No analysis"

				if exists {
					riskStr = item.Risk
					verdict = item.Reason
					lowerRisk := strings.ToLower(item.Risk)

					if strings.Contains(lowerRisk, "critical") {
						riskLvl = 4
					} else if strings.Contains(lowerRisk, "high") {
						riskLvl = 3
					} else if strings.Contains(lowerRisk, "medium") {
						riskLvl = 2
					} else if strings.Contains(lowerRisk, "manual") {
						riskLvl = 1
						riskStr = "MANUAL CHECK"
					}
				}
				aiResults = append(aiResults, AIResult{
					URL: r.URL, RiskLevel: riskLvl, RiskStr: riskStr, Verdict: verdict,
				})
			}
		} else {
			fmt.Println("⚠️ JSON Parse failed, saving raw text.")
			for _, r := range batch {
				aiResults = append(aiResults, AIResult{URL: r.URL, RiskLevel: 2, RiskStr: "Raw", Verdict: analysis})
			}
		}
	}

	elapsed := time.Since(startTime)
	fmt.Printf("\n✨ AI Analysis Complete in %s!\n", elapsed.Round(time.Second))

	if len(aiResults) > 0 {
		generateAIReport(reader, aiResults)
	}
}

func generateAIReport(reader *bufio.Reader, results []AIResult) {
	fmt.Print("\n📄 Generate AI Report? (y/n): ")
	gen, _ := reader.ReadString('\n')
	if strings.ToLower(strings.TrimSpace(gen)) != "y" {
		return
	}

	fmt.Println("\nSelect minimum risk level to include:")
	fmt.Println("1. Low+ (Show everything)")
	fmt.Println("2. Medium+ (Medium, High, Critical)")
	fmt.Println("3. High+ (High, Critical only)")
	fmt.Print("Choice (1-3): ")

	levelStr, _ := reader.ReadString('\n')
	minLevel := 1
	s := strings.TrimSpace(levelStr)
	if s == "2" {
		minLevel = 2
	}
	if s == "3" {
		minLevel = 3
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].RiskLevel > results[j].RiskLevel
	})

	file, err := os.Create("report_ai.md")
	if err != nil {
		fmt.Printf("❌ Error creating report: %v\n", err)
		return
	}
	defer file.Close()

	file.WriteString("# 🕵️ GoScope AI Security Report\n")
	file.WriteString(fmt.Sprintf("**Date:** %s\n\n", time.Now().Format(time.RFC1123)))
	file.WriteString("## 🚨 Security Findings (Sorted by Risk)\n\n")

	count := 0
	for _, r := range results {
		if r.RiskLevel >= minLevel {
			icon := "🔵" // Info/Low/Manual
			if r.RiskLevel == 2 {
				icon = "🟡"
			} // Medium
			if r.RiskLevel == 3 {
				icon = "🔴"
			} // High
			if r.RiskLevel == 4 {
				icon = "🔥"
			} // Critical

			file.WriteString(fmt.Sprintf("### %s [%s] %s\n", icon, r.RiskStr, r.URL))
			file.WriteString("**AI Analysis:**\n")
			file.WriteString("> " + strings.ReplaceAll(r.Verdict, "\n", "\n> ") + "\n\n")
			file.WriteString("---\n")
			count++
		}
	}

	fmt.Printf("\n✅ Report saved to 'report_ai.md' (%d findings included)\n", count)
}
