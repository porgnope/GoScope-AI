package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {

	reader := bufio.NewReader(os.Stdin)

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
		runHeadlessMode(reader)
	case "combo":
		runComboMode(reader)
	default:
		runScanMode(reader)
	}
}

func runScanMode(reader *bufio.Reader) {
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("GoCrawUz - Advanced URL Discovery Tool")
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

	fmt.Print("Enable response analysis? (y/n, default n): ")
	analysisStr, _ := reader.ReadString('\n')
	enableAnalysis := strings.ToLower(strings.TrimSpace(analysisStr)) == "y"

	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("🎯 Target: %s\n", targetURL)
	fmt.Printf("⚡ Threads: %d\n", threads)
	fmt.Printf("⏱️  RateLimit ms: %dms\n", rateLimitMs)
	fmt.Printf("🔍 SPA Detection: %v\n", enableSPA)
	fmt.Printf("📝 Verbose: %v\n", verbose)
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()

	scanner := NewScanner(targetURL, threads, enableSPA, verbose, enableAnalysis, rateLimitMs, randomUA)

	results, err := scanner.Scan()

	if err != nil {
		fmt.Printf("❌ Error: %v\n", err)
		return
	}

	displayResults(results, scanner, enableSPA)

	if enableBFS {
		results = runBFS(scanner, targetURL, results, bfsDepth, bfsMaxURLs, rateLimitMs)
	}

	saveResultsWithDedup(reader, results, scanner, enableSPA)
}

func runHeadlessMode(reader *bufio.Reader) {
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("GoCrawUz - Headless Browser Mode")
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

	saveURLsWithDedup(reader, allURLs)
}

func runComboMode(reader *bufio.Reader) {
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("GoCrawUz - COMBO Mode (Scan + Headless)")
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

	fmt.Print("Enable response analysis? (y/n, default n): ")
	analysisStr, _ := reader.ReadString('\n')
	enableAnalysis := strings.ToLower(strings.TrimSpace(analysisStr)) == "y"

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

	scanner := NewScanner(targetURL, threads, enableSPA, verbose, enableAnalysis, rateLimitMs, randomUA)

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

	// Объединение с дедупликацией, понял? это просто удаление дубликатов, но нужно было круто назвать
	opts := DefaultNormalizeOptions()
	allURLs := make(map[string]bool)

	for _, r := range scanResults {
		canonical := CanonicalizeURL(r.URL, opts)
		allURLs[canonical] = true
	}

	for _, route := range scanner.spaRoutes {
		// spaRoutes уже содержит полные URL, не нужно добавлять BaseURL, иначе будут склеенные
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

	fmt.Println("\n📋 Sample URLs (first 30):")
	for i, url := range finalURLs {
		if i >= 30 {
			break
		}
		fmt.Printf("  → %s\n", url)
	}

	if len(finalURLs) > 30 {
		fmt.Printf("\n... and %d more URLs\n", len(finalURLs)-30)
	}

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

		if len(apis) > 0 {
			fmt.Printf("\n🔌 API Endpoints (%d) - test with curl/Burp:\n", len(apis))
			for _, route := range apis {
				fmt.Printf("  • %s\n", route)
			}
		}

		if len(unknown) > 0 {
			fmt.Printf("\n❓ Unknown (%d) - needs investigation:\n", len(unknown))
			for _, route := range unknown {
				fmt.Printf("  • %s\n", route)
			}
		}
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

		fmt.Printf("\n✅ BFS discovered %d NEW URLs (total visited: %d)\n",
			newCount, len(bfsResults))

		if newCount > 0 {
			fmt.Println("\n📍 New URLs from BFS:")
			byStatus := make(map[int][]Result)
			for _, r := range bfsResults {
				if !existingURLs[r.URL] {
					byStatus[r.StatusCode] = append(byStatus[r.StatusCode], r)
				}
			}

			statuses := []int{200, 301, 302, 401, 403, 404, 405, 500}
			for _, status := range statuses {
				if urls, ok := byStatus[status]; ok && len(urls) > 0 {
					fmt.Printf("\n[%d] Found: %d\n", status, len(urls))
					for _, r := range urls {
						fmt.Printf("  → %s\n", r.URL)
					}
				}
			}
		}
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

	// Собираем все URL с дедупликацией
	opts := DefaultNormalizeOptions()
	uniqueURLs := make(map[string]string) // canonical -> original

	for _, r := range results {
		canonical := CanonicalizeURL(r.URL, opts)
		if _, exists := uniqueURLs[canonical]; !exists {
			uniqueURLs[canonical] = r.URL
		}
	}

	if enableSPA && len(scanner.spaRoutes) > 0 {
		for _, route := range scanner.spaRoutes {
			canonical := CanonicalizeURL(route, opts)
			if _, exists := uniqueURLs[canonical]; !exists {
				uniqueURLs[canonical] = route
			}
		}
	}

	urlsFile, err := os.Create("urls.txt")
	if err != nil {
		fmt.Printf("❌ Error: %v\n", err)
		return
	}
	defer urlsFile.Close()

	for _, url := range uniqueURLs {
		urlsFile.WriteString(url + "\n")
	}

	totalBefore := len(results)
	if enableSPA {
		totalBefore += len(scanner.spaRoutes)
	}
	removed := totalBefore - len(uniqueURLs)

	fmt.Printf("✅ Saved to urls.txt\n")
	fmt.Printf("   └─ Total: %d unique URLs", len(uniqueURLs))
	if removed > 0 {
		fmt.Printf(" (removed %d duplicates)", removed)
	}
	fmt.Println()

	fmt.Println("\n✨ Done!")
}

func saveURLsWithDedup(reader *bufio.Reader, urls []string) {
	fmt.Print("\n💾 Save results? (y/n): ")
	save, _ := reader.ReadString('\n')

	if strings.ToLower(strings.TrimSpace(save)) != "y" {
		fmt.Println("\n✨ Done!")
		return
	}

	// Дедупликация, я уже говорил что это звучит КРУТО??
	opts := DefaultNormalizeOptions()
	uniqueURLs := make(map[string]string)

	for _, url := range urls {
		canonical := CanonicalizeURL(url, opts)
		if _, exists := uniqueURLs[canonical]; !exists {
			uniqueURLs[canonical] = url
		}
	}

	urlsFile, err := os.Create("urls.txt")
	if err != nil {
		fmt.Printf("❌ Error: %v\n", err)
		return
	}
	defer urlsFile.Close()

	for _, url := range uniqueURLs {
		urlsFile.WriteString(url + "\n")
	}

	removed := len(urls) - len(uniqueURLs)

	fmt.Printf("✅ Saved to urls.txt\n")
	fmt.Printf("   └─ Total: %d unique URLs", len(uniqueURLs))
	if removed > 0 {
		fmt.Printf(" (removed %d duplicates)", removed)
	}
	fmt.Println()

	fmt.Println("\n✨ Done!")
}

func classifyRoute(path string) string {
	apiPatterns := []string{
		"/auth/refresh",
		"/auth/activate",
		"/auth/captcha",
		"/auth/sign-in",
		"/auth/sign-up",
		"/ping",
		"/users/stats",
		"/api/",
		"/graphql",
	}

	for _, pattern := range apiPatterns {
		if strings.HasPrefix(path, pattern) {
			return "api"
		}
	}

	pagePatterns := []string{
		"/home/",
		"/account/login",
		"/account/register",
		"/account/forgot-pass",
		"/wiki/",
		"/profile",
		"/banlist",
		"/dashboard",
		"/settings",
	}

	for _, pattern := range pagePatterns {
		if strings.HasPrefix(path, pattern) {
			return "page"
		}
	}

	return "unknown"
}
