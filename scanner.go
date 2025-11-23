package main

import (
	"bufio"
	"context"
	"crypto/md5"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
)

type Result struct {
	URL        string
	StatusCode int
	IsSPARoute bool
}

type Scanner struct {
	BaseURL    string
	Threads    int
	EnableSPA  bool
	DelayMs    int
	Verbose    bool
	Wordlist   []string
	Baseline   BaselineInfo
	httpClient *http.Client
	spaRoutes  []string
	jsFiles    []string
	mu         sync.Mutex
}

type BaselineInfo struct {
	NotFoundHash   string
	HomeHash       string
	NotFoundLength int
	IsSPA          bool
	SPAMarkers     []string
	ForbiddenHash  string // Baseline для generic 403 страниц
}

func NewScanner(baseURL string, threads int, enableSPA bool, delayMs int, verbose bool) *Scanner {
	return &Scanner{
		BaseURL:   strings.TrimRight(baseURL, "/"),
		Threads:   threads,
		EnableSPA: enableSPA,
		DelayMs:   delayMs,
		Verbose:   verbose,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				IdleConnTimeout:     90 * time.Second,
				TLSHandshakeTimeout: 5 * time.Second,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (s *Scanner) logVerbose(format string, args ...interface{}) {
	if s.Verbose {
		log.Printf("[DEBUG] "+format, args...)
	}
}

func (s *Scanner) Scan() ([]Result, error) {
	fmt.Println("📂 Loading wordlist...")
	if err := s.loadWordlist("common.txt"); err != nil {
		return nil, fmt.Errorf("failed to load wordlist: %w", err)
	}
	fmt.Printf("✅ Loaded: %d paths\n", len(s.Wordlist))

	fmt.Println("\n🔍 Fingerprinting baseline...")
	if err := s.getBaseline(); err != nil {
		return nil, fmt.Errorf("failed to fingerprint baseline: %w", err)
	}

	if s.EnableSPA && s.Baseline.IsSPA {
		fmt.Println("\n🔎 Extracting endpoints from JS (GoLinkFinder method)...")
		if err := s.extractEndpointsFromJS(); err != nil {
			s.logVerbose("Warning: JS extraction failed: %v", err)
		}
		if len(s.spaRoutes) > 0 {
			fmt.Printf("✅ Found %d potential endpoints\n", len(s.spaRoutes))
		}
	}

	fmt.Println("\n⚡ Starting scan...\n")
	results := s.fuzz()

	return results, nil
}

func (s *Scanner) loadWordlist(filename string) error {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		s.logVerbose("Wordlist not found, creating default: %s", filename)
		return s.createDefaultWordlist(filename)
	}

	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed to open wordlist: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Фильтруем комментарии и плейсхолдеры
		if line != "" && !strings.HasPrefix(line, "#") && !strings.Contains(line, "%EXT%") {
			s.Wordlist = append(s.Wordlist, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading wordlist: %w", err)
	}

	return nil
}

func (s *Scanner) createDefaultWordlist(filename string) error {
	paths := []string{
		"/api/", "/api/v1/", "/api/v2/", "/api/auth/", "/api/users/",
		"/graphql/", "/admin/", "/login/", "/register/",
		"/wp-admin/", "/wp-content/", "/.env", "/.git/",
		"/assets/", "/static/", "/manifest.json", "/robots.txt",
	}

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create wordlist: %w", err)
	}
	defer file.Close()

	for _, p := range paths {
		if _, err := file.WriteString(p + "\n"); err != nil {
			return fmt.Errorf("failed to write wordlist: %w", err)
		}
	}

	s.Wordlist = paths
	fmt.Printf("✅ Created default wordlist (%d paths)\n", len(paths))
	return nil
}

func (s *Scanner) getBaseline() error {
	// Baseline для 404
	randPath := fmt.Sprintf("/nonexistent-%d-%s", time.Now().Unix(), randString(8))
	notFoundHash, _, err := s.fetchPage(s.BaseURL + randPath)
	if err != nil {
		return fmt.Errorf("failed to fetch 404 baseline: %w", err)
	}

	// Baseline для homepage
	homeHash, homeBody, err := s.fetchPage(s.BaseURL)
	if err != nil {
		return fmt.Errorf("failed to fetch homepage: %w", err)
	}

	// Baseline для 403 (критично для точности!)
	forbiddenHash, _, _ := s.fetchPage(s.BaseURL + "/api/nonexistent-test-" + randString(8))

	isSPA := notFoundHash == homeHash
	spaMarkers := detectSPAMarkers(homeBody)

	s.Baseline = BaselineInfo{
		NotFoundHash:  notFoundHash,
		HomeHash:      homeHash,
		IsSPA:         isSPA,
		SPAMarkers:    spaMarkers,
		ForbiddenHash: forbiddenHash,
	}

	if s.Baseline.IsSPA {
		fmt.Printf("🔍 SPA detected (markers: %v)\n", spaMarkers)
	}

	if forbiddenHash != "" {
		s.logVerbose("Forbidden baseline: hash=%s", forbiddenHash[:10])
	}

	return nil
}

func detectSPAMarkers(html string) []string {
	markers := []string{}
	checks := map[string][]string{
		"React":   {`id="root"`, `ReactDOM`, `__REACT`, `react.production`, `react-dom`},
		"Vue":     {`id="app"`, `createApp`, `Vue.`, `vue.runtime`, `_Vue`},
		"Angular": {`ng-app`, `ng-version`, `angular.js`, `@angular/core`},
		"Svelte":  {`svelte-`, `__svelte`, `svelte.internal`},
		"Next.js": {`__NEXT_DATA__`, `_next/static`, `next.js`},
		"Nuxt.js": {`__NUXT__`, `_nuxt/`, `nuxt.js`},
		"Gatsby":  {`___gatsby`, `gatsby-`, `.cache/`},
		"Ember":   {`ember-application`, `Ember.`, `ember.js`},
	}

	for framework, patterns := range checks {
		for _, pattern := range patterns {
			if strings.Contains(html, pattern) {
				markers = append(markers, framework)
				break
			}
		}
	}
	return markers
}

func (s *Scanner) extractEndpointsFromJS() error {
	req, err := http.NewRequest("GET", s.BaseURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch page: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read body: %w", err)
	}
	html := string(body)

	htmlEndpoints := s.extractEndpoints(html, s.BaseURL)
	s.logVerbose("Found %d endpoints in HTML", len(htmlEndpoints))

	allJSFiles := s.findAllJSFiles(html)
	s.logVerbose("Found %d JS files total", len(allJSFiles))

	var jsFiles []string
	baseHost := ""
	if u, err := url.Parse(s.BaseURL); err == nil {
		baseHost = u.Host
	}

	for _, jsURL := range allJSFiles {
		if u, err := url.Parse(jsURL); err == nil {
			if u.Host == baseHost || u.Host == "" {
				jsFiles = append(jsFiles, jsURL)
			} else {
				s.logVerbose("Skipping external JS: %s", jsURL)
			}
		}
	}
	s.logVerbose("Found %d local JS files", len(jsFiles))

	endpointSet := make(map[string]bool)

	for _, ep := range htmlEndpoints {
		endpointSet[ep] = true
	}

	for i, jsURL := range jsFiles {
		s.logVerbose("Parsing JS file %d/%d: %s", i+1, len(jsFiles), jsURL)

		jsReq, err := http.NewRequest("GET", jsURL, nil)
		if err != nil {
			if s.Verbose {
				fmt.Printf("⚠️  Warning: Failed to create request for %s: %v\n", jsURL, err)
			}
			continue
		}

		jsResp, err := s.httpClient.Do(jsReq)
		if err != nil {
			if s.Verbose {
				fmt.Printf("⚠️  Warning: Failed to fetch %s: %v\n", jsURL, err)
			}
			continue
		}

		limitedReader := io.LimitReader(jsResp.Body, 10*1024*1024)
		jsBody, err := io.ReadAll(limitedReader)
		jsResp.Body.Close()
		if err != nil {
			if s.Verbose {
				fmt.Printf("⚠️  Warning: Failed to read %s: %v\n", jsURL, err)
			}
			continue
		}

		s.logVerbose("Downloaded %d bytes from %s", len(jsBody), jsURL)

		jsEndpoints := s.extractEndpoints(string(jsBody), s.BaseURL)
		s.logVerbose("Found %d endpoints in %s", len(jsEndpoints), jsURL)

		for _, ep := range jsEndpoints {
			endpointSet[ep] = true
		}
	}

	for endpoint := range endpointSet {
		normalized := s.normalizeEndpoint(endpoint)
		if normalized != "" && !contains(s.spaRoutes, normalized) {
			s.spaRoutes = append(s.spaRoutes, normalized)
		}
	}

	s.logVerbose("Total normalized endpoints: %d", len(s.spaRoutes))

	return nil
}

func (s *Scanner) extractEndpoints(content, baseURL string) []string {
	endpoints := []string{}

	patterns := []*regexp.Regexp{
		// React Router
		regexp.MustCompile(`<Route[^>]+path=["']([/a-zA-Z0-9_\-:]+)["']`),
		regexp.MustCompile(`path:\s*["']([/a-zA-Z0-9_\-:]+)["']`),

		// Vue Router
		regexp.MustCompile(`\{\s*path:\s*["']([/a-zA-Z0-9_\-:]+)["']`),

		// API endpoints
		regexp.MustCompile(`(?:fetch|axios|http)\s*\(\s*["']([/a-zA-Z0-9_\-/]+)["']`),
		regexp.MustCompile(`(?:get|post|put|delete|patch)\s*\(\s*["']([/a-zA-Z0-9_\-/]+)["']`),

		// GraphQL
		regexp.MustCompile(`["'](?i)(/graphql[/a-zA-Z0-9_\-]*)["']`),

		// REST API
		regexp.MustCompile(`["'](/api/[a-zA-Z0-9_\-/]+)["']`),

		// Navigation
		regexp.MustCompile(`to:\s*["']([/a-zA-Z0-9_\-]+)["']`),
		regexp.MustCompile(`href:\s*["']([/a-zA-Z0-9_\-]+)["']`),

		// Generic paths
		regexp.MustCompile(`["']([/][a-zA-Z][a-zA-Z0-9_\-/]{2,})["']`),
	}

	for _, pattern := range patterns {
		matches := pattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 1 && match[1] != "" {
				endpoints = append(endpoints, match[1])
			}
		}
	}

	return endpoints
}

func (s *Scanner) normalizeEndpoint(endpoint string) string {
	endpoint = strings.Split(endpoint, "?")[0]
	endpoint = strings.Split(endpoint, "#")[0]

	if !strings.HasPrefix(endpoint, "/") && !strings.HasPrefix(endpoint, "http") {
		endpoint = "/" + endpoint
	}

	if strings.HasPrefix(endpoint, "http") {
		u, err := url.Parse(endpoint)
		if err != nil {
			return ""
		}
		baseU, _ := url.Parse(s.BaseURL)
		if u.Host != baseU.Host {
			return ""
		}
		endpoint = u.Path
	}

	if len(endpoint) < 2 || len(endpoint) > 100 {
		return ""
	}

	if hasFileExtension(endpoint) {
		return ""
	}

	if strings.Contains(endpoint, "//") || strings.Contains(endpoint, "\\") {
		return ""
	}

	mimeTypes := []string{
		"/application/", "/multipart/", "/text/",
		"/image/", "/video/", "/audio/",
	}
	for _, mime := range mimeTypes {
		if strings.HasPrefix(endpoint, mime) {
			return ""
		}
	}

	blacklist := []string{
		"node_modules", "webpack", "__webpack", "hot-update",
		"/gs/", "/gtag/", "/g/collect", "/pagead/", "/ddm/",
		"/mc/collect", "//s.w.org", "//assets.squarespace.com",
		"/_/service_worker", "/debug/", "conversion", "/ccm/", "/measurement/",
	}
	for _, bl := range blacklist {
		if strings.Contains(endpoint, bl) {
			return ""
		}
	}

	parts := strings.Split(strings.Trim(endpoint, "/"), "/")

	if len(parts) >= 2 {
		shortSegments := 0
		for _, part := range parts {
			if len(part) <= 2 {
				shortSegments++
			}
		}
		if shortSegments > len(parts)/2 {
			return ""
		}
	}

	if len(parts) == 1 {
		knownSections := []string{
			"home", "account", "admin", "auth", "login", "register",
			"profile", "settings", "dashboard", "wiki", "banlist",
			"shop", "forum", "news", "about", "contact", "help",
			"api", "users", "stats", "map", "launcher", "rules",
			"vote", "donate", "staff", "team", "status", "ping",
		}

		word := strings.ToLower(parts[0])
		found := false
		for _, known := range knownSections {
			if word == known {
				found = true
				break
			}
		}

		if !found {
			return ""
		}
	}

	endpoint = regexp.MustCompile(`:[a-zA-Z]+`).ReplaceAllString(endpoint, "test")

	return endpoint
}

func (s *Scanner) findAllJSFiles(html string) []string {
	jsSet := make(map[string]bool)

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`<script[^>]+src=["']([^"']+)["']`),
		regexp.MustCompile(`["'](https?://[^"']+\.js)["']`),
		regexp.MustCompile(`["']([/][^"']+\.js)["']`),
	}

	for _, pattern := range patterns {
		matches := pattern.FindAllStringSubmatch(html, -1)
		for _, match := range matches {
			if len(match) > 1 {
				jsURL := match[1]
				if !strings.HasPrefix(jsURL, "http") {
					if !strings.HasPrefix(jsURL, "/") {
						jsURL = "/" + jsURL
					}
					jsURL = s.BaseURL + jsURL
				}
				jsSet[jsURL] = true
			}
		}
	}

	var result []string
	for js := range jsSet {
		result = append(result, js)
	}
	return result
}

func (s *Scanner) fuzz() []Result {
	var results []Result
	var mu sync.Mutex
	found := make(map[string]bool)

	allPaths := make([]string, 0, len(s.Wordlist)+len(s.spaRoutes))
	allPaths = append(allPaths, s.Wordlist...)
	allPaths = append(allPaths, s.spaRoutes...)

	total := len(allPaths)
	completed := 0

	eg := errgroup.Group{}
	sem := make(chan struct{}, s.Threads)

	for _, path := range allPaths {
		path := path
		sem <- struct{}{}

		eg.Go(func() error {
			defer func() { <-sem }()

			if s.DelayMs > 0 {
				time.Sleep(time.Millisecond * time.Duration(s.DelayMs))
			}

			if !strings.HasPrefix(path, "/") {
				path = "/" + path
			}
			fullURL := s.BaseURL + path

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
			if err != nil {
				s.logVerbose("Failed to create request for %s: %v", fullURL, err)
				return nil
			}

			resp, err := s.httpClient.Do(req)
			if err != nil {
				s.logVerbose("Failed to fetch %s: %v", fullURL, err)
				return nil
			}

			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				s.logVerbose("Failed to read body for %s: %v", fullURL, err)
				return nil
			}

			status := resp.StatusCode
			hash := fmt.Sprintf("%x", md5.Sum(body))

			mu.Lock()
			completed++
			progress := float64(completed) / float64(total) * 100
			foundCount := len(results)
			mu.Unlock()

			fmt.Printf("\r⏳ Progress: %d/%d (%.1f%%) | Found: %d   ",
				completed, total, progress, foundCount)

			if s.isValid(status, hash, string(body), path) {
				mu.Lock()
				if !found[fullURL] {
					found[fullURL] = true
					isSPARoute := contains(s.spaRoutes, path)
					results = append(results, Result{
						URL:        fullURL,
						StatusCode: status,
						IsSPARoute: isSPARoute,
					})
					s.logVerbose("Found: [%d] %s", status, fullURL)
				}
				mu.Unlock()
			}

			return nil
		})
	}

	eg.Wait()
	fmt.Println()

	return results
}

func (s *Scanner) fetchPage(urlStr string) (string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		return "", "", fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("failed to fetch: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("failed to read body: %w", err)
	}

	hash := fmt.Sprintf("%x", md5.Sum(body))

	return hash, string(body), nil
}

func (s *Scanner) isValid(status int, hash, body, path string) bool {
	// 403 - фильтруем generic forbidden pages (критично для точности!)
	if status == 403 {
		// Если hash совпадает с baseline 403 - это ложное срабатывание
		if s.Baseline.ForbiddenHash != "" && hash == s.Baseline.ForbiddenHash {
			s.logVerbose("Skipping %s - generic 403 page (hash: %s)", path, hash[:10])
			return false
		}
		// Уникальная 403 страница - сохраняем (реальный endpoint)
		s.logVerbose("Found unique 403: %s (hash: %s)", path, hash[:10])
		return true
	}

	if status == 401 || status == 405 || status == 500 {
		return true
	}

	if status == 301 || status == 302 {
		if s.Baseline.IsSPA {
			return false
		}
		return true
	}

	if status == 200 {
		if isStaticFile(path) {
			return hash != s.Baseline.HomeHash && hash != s.Baseline.NotFoundHash
		}

		if s.Baseline.IsSPA {
			return hash != s.Baseline.NotFoundHash
		}

		return hash != s.Baseline.NotFoundHash && hash != s.Baseline.HomeHash
	}

	return false
}

func hasFileExtension(path string) bool {
	exts := []string{".js", ".css", ".png", ".jpg", ".ico", ".json", ".txt", ".xml", ".woff", ".ttf", ".svg"}
	for _, ext := range exts {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

func isStaticFile(path string) bool {
	return hasFileExtension(path)
}

func randString(n int) string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return string(b)
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
