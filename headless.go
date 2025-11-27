package main

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

type HeadlessScanner struct {
	BaseURL       string
	MaxPages      int
	Timeout       time.Duration
	CollectDelay  time.Duration
	EnableDeep    bool
	visited       map[string]bool
	discoveredAPI []string
	mu            sync.Mutex
}

func NewHeadlessScanner(baseURL string, maxPages int, enableDeep bool) *HeadlessScanner {
	return &HeadlessScanner{
		BaseURL:       baseURL,
		MaxPages:      maxPages,
		Timeout:       30 * time.Second,
		CollectDelay:  3 * time.Second,
		EnableDeep:    enableDeep, //
		visited:       make(map[string]bool),
		discoveredAPI: []string{},
	}
}

type HeadlessResult struct {
	URL         string
	Links       []string
	APIRequests []string
	StatusCode  int
}

func (h *HeadlessScanner) Scan() ([]HeadlessResult, error) {
	fmt.Println("\n🌐 Starting headless browser scan...")
	fmt.Printf("📊 Max pages: %d | Deep mode: %v | Timeout: %v\n\n",
		h.MaxPages, h.EnableDeep, h.Timeout)

	results := []HeadlessResult{}
	queue := []string{h.BaseURL}
	h.visited[h.BaseURL] = true

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
	)

	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer allocCancel()

	for len(queue) > 0 && len(results) < h.MaxPages {
		currentURL := queue[0]
		queue = queue[1:]

		fmt.Printf("\r🔍 Scanning [%d/%d]: %s   ",
			len(results)+1, h.MaxPages, truncateURL(currentURL, 60))

		result, err := h.crawlPage(allocCtx, currentURL)
		if err != nil {
			continue
		}

		results = append(results, result)

		opts := DefaultNormalizeOptions()
		for _, link := range result.Links {
			abs, err := ToAbsoluteURL(link, currentURL)
			if err != nil || abs == "" {
				continue
			}

			if !IsInScope(abs, h.BaseURL, "/") {
				continue
			}

			canonical := CanonicalizeURL(abs, opts)

			h.mu.Lock()
			if !h.visited[canonical] && len(results) < h.MaxPages {
				h.visited[canonical] = true
				queue = append(queue, abs)
			}
			h.mu.Unlock()
		}
	}

	fmt.Println("\n\n✅ Headless scan complete!")

	return results, nil
}

func (h *HeadlessScanner) crawlPage(allocCtx context.Context, url string) (HeadlessResult, error) {
	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel() // освобождается после каждой страницы

	ctx, timeoutCancel := context.WithTimeout(ctx, h.Timeout)
	defer timeoutCancel()

	result := HeadlessResult{
		URL:         url,
		Links:       []string{},
		APIRequests: []string{},
	}

	apiRequests := []string{}
	if h.EnableDeep {
		chromedp.ListenTarget(ctx, func(ev interface{}) {
			switch ev := ev.(type) {
			case *network.EventRequestWillBeSent:
				reqURL := ev.Request.URL
				if strings.Contains(reqURL, "/api/") ||
					strings.Contains(reqURL, "/graphql") ||
					strings.HasSuffix(reqURL, ".json") {
					apiRequests = append(apiRequests, reqURL)
				}
			}
		})
	}

	var links []string
	var statusCode int64

	err := chromedp.Run(ctx,
		network.Enable(),
		chromedp.Navigate(url),
		chromedp.WaitVisible(`body`, chromedp.ByQuery),
		chromedp.Sleep(h.CollectDelay),

		chromedp.Evaluate(`
            Array.from(document.querySelectorAll('a[href], link[href], area[href]'))
                .map(el => el.href)
                .filter(href => href && href.startsWith('http'))
        `, &links),

		chromedp.Evaluate(`window.performance?.getEntriesByType?.('navigation')?.[0]?.responseStatus || 200`, &statusCode),
	)

	if err != nil {
		return result, err
	}

	result.Links = links
	result.APIRequests = apiRequests
	result.StatusCode = int(statusCode)

	return result, nil
}

func (h *HeadlessScanner) GetAllURLs(results []HeadlessResult) []string {
	opts := DefaultNormalizeOptions()
	seen := make(map[string]bool)
	urls := []string{}

	for _, result := range results {
		canonical := CanonicalizeURL(result.URL, opts)
		if !seen[canonical] {
			seen[canonical] = true
			urls = append(urls, result.URL)
		}

		for _, link := range result.Links {
			abs, err := ToAbsoluteURL(link, result.URL)
			if err != nil || abs == "" {
				continue
			}

			if !IsInScope(abs, h.BaseURL, "/") {
				continue
			}

			canonical := CanonicalizeURL(abs, opts)
			if !seen[canonical] {
				seen[canonical] = true
				urls = append(urls, abs)
			}
		}

		for _, api := range result.APIRequests {
			abs, err := ToAbsoluteURL(api, result.URL)
			if err != nil || abs == "" {
				continue
			}

			canonical := CanonicalizeURL(abs, opts)
			if !seen[canonical] {
				seen[canonical] = true
				urls = append(urls, abs)
			}
		}
	}

	return urls
}
