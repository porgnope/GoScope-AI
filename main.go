package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func main() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("GoHidden - Advanced URL Discovery Tool")
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

	fmt.Print("Delay between requests (ms, default 0): ")
	delayStr, _ := reader.ReadString('\n')
	delay := 0
	if d, err := strconv.Atoi(strings.TrimSpace(delayStr)); err == nil && d >= 0 {
		delay = d
	}

	fmt.Print("Enable SPA route detection? (y/n, default y): ")
	spaDetect, _ := reader.ReadString('\n')
	enableSPA := strings.ToLower(strings.TrimSpace(spaDetect)) != "n"

	fmt.Print("Verbose mode? (y/n, default n): ")
	verboseStr, _ := reader.ReadString('\n')
	verbose := strings.ToLower(strings.TrimSpace(verboseStr)) == "y"

	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("🎯 Target: %s\n", targetURL)
	fmt.Printf("⚡ Threads: %d\n", threads)
	fmt.Printf("⏱️  Delay: %dms\n", delay)
	fmt.Printf("🔍 SPA Detection: %v\n", enableSPA)
	fmt.Printf("📝 Verbose: %v\n", verbose)
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()

	scanner := NewScanner(targetURL, threads, enableSPA, delay, verbose)
	results, err := scanner.Scan()

	if err != nil {
		fmt.Printf("❌ Error: %v\n", err)
		return
	}

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
				fmt.Printf("  • %s%s\n", scanner.BaseURL, route)
			}
		}

		if len(apis) > 0 {
			fmt.Printf("\n🔌 API Endpoints (%d) - test with curl/Burp:\n", len(apis))
			for _, route := range apis {
				fmt.Printf("  • %s%s\n", scanner.BaseURL, route)
			}
		}

		if len(unknown) > 0 {
			fmt.Printf("\n❓ Unknown (%d) - needs investigation:\n", len(unknown))
			for _, route := range unknown {
				fmt.Printf("  • %s%s\n", scanner.BaseURL, route)
			}
		}
	}

	fmt.Print("\n💾 Save results? (y/n): ")
	save, _ := reader.ReadString('\n')

	if strings.ToLower(strings.TrimSpace(save)) == "y" {
		// Текстовый файл со статусами
		txtFile, err := os.Create("results.txt")
		if err != nil {
			fmt.Printf("❌ Error: %v\n", err)
			return
		}
		defer txtFile.Close()

		txtFile.WriteString("# Confirmed endpoints\n")
		for _, r := range results {
			txtFile.WriteString(fmt.Sprintf("[%d] %s\n", r.StatusCode, r.URL))
		}

		if enableSPA && len(scanner.spaRoutes) > 0 {
			txtFile.WriteString("\n# Potential SPA routes\n")
			for _, route := range scanner.spaRoutes {
				txtFile.WriteString(scanner.BaseURL + route + "\n")
			}
		}

		// Файл с чистыми URL (для ffuf/nuclei)
		urlsFile, err := os.Create("urls.txt")
		if err != nil {
			fmt.Printf("⚠️  Warning: Could not create urls.txt: %v\n", err)
		} else {
			defer urlsFile.Close()

			for _, r := range results {
				urlsFile.WriteString(r.URL + "\n")
			}

			if enableSPA && len(scanner.spaRoutes) > 0 {
				for _, route := range scanner.spaRoutes {
					urlsFile.WriteString(scanner.BaseURL + route + "\n")
				}
			}

			fmt.Printf("✅ Saved to results.txt and urls.txt\n")
		}
	}

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
