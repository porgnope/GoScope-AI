package main

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sync"
	"time"
)

// настройки для BFS-краулера
type CrawlConfig struct {
	MaxDepth  int           // Максимальная глубина обхода
	RateLimit time.Duration // Задержка между запросами
	MaxURLs   int           // Максимальное количество URL для обхода
}

// узел в очереди обхода
type CrawlNode struct {
	URL   string
	Depth int
}

// автоматический краулер с BFS-обходом
type BFSCrawler struct {
	scanner *Scanner
	config  CrawlConfig
	queue   []CrawlNode
	visited map[string]bool
	mu      sync.Mutex
	allURLs []Result
}

// создаёт новый BFS-краулер
func NewBFSCrawler(scanner *Scanner, config CrawlConfig) *BFSCrawler {
	return &BFSCrawler{
		scanner: scanner,
		config:  config,
		queue:   []CrawlNode{},
		visited: make(map[string]bool),
		allURLs: []Result{},
	}
}

// Crawl запускает автоматический обход
func (c *BFSCrawler) Crawl(startURL string) ([]Result, error) {
	opts := DefaultNormalizeOptions()
	startCanonical := CanonicalizeURL(startURL, opts)

	// Добавляем стартовый URL в очередь
	c.queue = append(c.queue, CrawlNode{URL: startURL, Depth: 0})
	c.visited[startCanonical] = true

	fmt.Println("\n🔄 Starting BFS crawl...")
	fmt.Printf("📊 Max depth: %d | Rate: %v | Max URLs: %d\n\n",
		c.config.MaxDepth, c.config.RateLimit, c.config.MaxURLs)

	visitedCount := 0

	for len(c.queue) > 0 && visitedCount < c.config.MaxURLs {
		// Извлекаем первый элемент из очереди
		current := c.queue[0]
		c.queue = c.queue[1:]

		if current.Depth > c.config.MaxDepth {
			continue
		}

		visitedCount++
		fmt.Printf("\r🌐 Visiting [%d/%d, depth %d]: %s   ",
			visitedCount, c.config.MaxURLs, current.Depth, truncateURL(current.URL, 60))

		// Запрашиваем страницу
		links, status := c.fetchAndExtractLinks(current.URL)

		if status > 0 {
			c.mu.Lock()
			c.allURLs = append(c.allURLs, Result{
				URL:        current.URL,
				StatusCode: status,
				IsSPARoute: false,
			})
			c.mu.Unlock()
		}

		// Добавляем найденные ссылки в очередь
		if current.Depth < c.config.MaxDepth {
			for _, link := range links {
				abs, err := ToAbsoluteURL(link, current.URL)
				if err != nil || abs == "" {
					continue
				}

				if !IsInScope(abs, c.scanner.BaseURL, "/") {
					continue
				}

				canonical := CanonicalizeURL(abs, opts)

				c.mu.Lock()
				if !c.visited[canonical] {
					c.visited[canonical] = true
					c.queue = append(c.queue, CrawlNode{
						URL:   abs,
						Depth: current.Depth + 1,
					})
				}
				c.mu.Unlock()
			}
		}

		// задержка между запросами
		if c.config.RateLimit > 0 {
			time.Sleep(c.config.RateLimit)
		}
	}

	fmt.Println("\n\n✅ BFS crawl complete!")
	return c.allURLs, nil
}

// запрашиваем страницу и извлекаем все ссылки
func (c *BFSCrawler) fetchAndExtractLinks(urlStr string) ([]string, int) {
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return nil, 0
	}

	resp, err := c.scanner.httpClient.Do(req)
	if err != nil {
		return nil, 0
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode
	}

	html := string(body)
	links := c.extractLinks(html)

	return links, resp.StatusCode
}

// извлекаем все ссылки из HTML
func (c *BFSCrawler) extractLinks(html string) []string {
	links := []string{}
	seen := make(map[string]bool)

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`<a[^>]+href=["']([^"']+)["']`),
		regexp.MustCompile(`<link[^>]+href=["']([^"']+)["']`),
		regexp.MustCompile(`<iframe[^>]+src=["']([^"']+)["']`),
		regexp.MustCompile(`<img[^>]+src=["']([^"']+)["']`),
		regexp.MustCompile(`<form[^>]+action=["']([^"']+)["']`),
	}

	for _, pattern := range patterns {
		matches := pattern.FindAllStringSubmatch(html, -1)
		for _, match := range matches {
			if len(match) > 1 && match[1] != "" {
				link := match[1]
				if !seen[link] {
					seen[link] = true
					links = append(links, link)
				}
			}
		}
	}

	return links
}

// обрезаем URL для удобного вывода
func truncateURL(url string, maxLen int) string {
	if len(url) <= maxLen {
		return url
	}
	return url[:maxLen-3] + "..."
}

// CrawlMultiple запускает обход с нескольких начальных URL
func (c *BFSCrawler) CrawlMultiple(startURLs []string) ([]Result, error) {
	opts := DefaultNormalizeOptions()

	// Добавляем все стартовые URL в очередь
	for _, url := range startURLs {
		canonical := CanonicalizeURL(url, opts)
		if !c.visited[canonical] {
			c.queue = append(c.queue, CrawlNode{URL: url, Depth: 0})
			c.visited[canonical] = true
		}
	}

	fmt.Println("\n🔄 Starting BFS crawl...")
	fmt.Printf("📊 Seeds: %d | Max depth: %d | Rate: %v | Max URLs: %d\n\n",
		len(startURLs), c.config.MaxDepth, c.config.RateLimit, c.config.MaxURLs)

	visitedCount := 0

	for len(c.queue) > 0 && visitedCount < c.config.MaxURLs {
		current := c.queue[0]
		c.queue = c.queue[1:]

		if current.Depth > c.config.MaxDepth {
			continue
		}

		visitedCount++
		fmt.Printf("\r🌐 Visiting [%d/%d, depth %d]: %s   ",
			visitedCount, c.config.MaxURLs, current.Depth, truncateURL(current.URL, 60))

		links, status := c.fetchAndExtractLinks(current.URL)

		if status > 0 {
			c.mu.Lock()
			c.allURLs = append(c.allURLs, Result{
				URL:        current.URL,
				StatusCode: status,
				IsSPARoute: false,
			})
			c.mu.Unlock()
		}

		if current.Depth < c.config.MaxDepth {
			for _, link := range links {
				abs, err := ToAbsoluteURL(link, current.URL)
				if err != nil || abs == "" {
					continue
				}

				if !IsInScope(abs, c.scanner.BaseURL, "/") {
					continue
				}

				canonical := CanonicalizeURL(abs, opts)

				c.mu.Lock()
				if !c.visited[canonical] {
					c.visited[canonical] = true
					c.queue = append(c.queue, CrawlNode{
						URL:   abs,
						Depth: current.Depth + 1,
					})
				}
				c.mu.Unlock()
			}
		}

		if c.config.RateLimit > 0 {
			time.Sleep(c.config.RateLimit)
		}
	}

	fmt.Println("\n\n✅ BFS crawl complete!")
	return c.allURLs, nil
}

//later SDB
