package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

var (
	RefreshMinutes = getEnvInt("REFRESH_MINUTES", 30)
	MaxGoroutines  = getEnvInt("MAX_GOROUTINES", 5)
	GithubToken    = os.Getenv("GITHUB_TOKEN")
	RunPort        = getEnv("PORT", "10010")
)

var (
	cachedData APIData
	cacheMutex sync.RWMutex
	httpClient = &http.Client{
		Timeout: 30 * time.Second,
	}
)

type RepoInfo struct {
	Stars     int    `json:"stars"`
	UpdatedAt string `json:"updated_at"`
	Version   string `json:"version"`
}

type PluginInfo struct {
	Desc       string   `json:"desc"`
	Repo       string   `json:"repo"`
	Tags       []string `json:"tags,omitempty"`
	SocialLink string   `json:"social_link"`
	Stars      int      `json:"stars"`
	UpdatedAt  string   `json:"updated_at"`
	Version    string   `json:"version"`
}

type APIData struct {
	Releases json.RawMessage       `json:"releases"`
	Plugins  map[string]PluginInfo `json:"plugins"`
	LastSync time.Time             `json:"last_sync"`
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if i, err := strconv.Atoi(value); err == nil {
			return i
		}
	}
	return defaultValue
}

func makeRequest(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/vnd.github.v3+json")
	if GithubToken != "" {
		req.Header.Set("Authorization", "token "+GithubToken)
	}

	return httpClient.Do(req)
}

func handleRateLimit(resp *http.Response) error {
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		// 检查 retry-after 响应头
		if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
			if seconds, err := strconv.Atoi(retryAfter); err == nil && seconds > 0 {
				log.Printf("Rate limited, waiting %d seconds (retry-after)", seconds)
				time.Sleep(time.Duration(seconds) * time.Second)
				return fmt.Errorf("rate limited")
			}
		}

		// 检查 x-ratelimit-remaining 和 x-ratelimit-reset
		remaining := resp.Header.Get("X-RateLimit-Remaining")
		if remaining != "" {
			if remainingCount, err := strconv.Atoi(remaining); err == nil && remainingCount == 0 {
				if resetTime := resp.Header.Get("X-RateLimit-Reset"); resetTime != "" {
					if resetTimestamp, err := strconv.ParseInt(resetTime, 10, 64); err == nil {
						waitTime := time.Until(time.Unix(resetTimestamp, 0))
						if waitTime > 0 {
							log.Printf("Rate limited, waiting until reset time: %v", waitTime)
							time.Sleep(waitTime)
							return fmt.Errorf("rate limited")
						}
					}
				}
			}
		}

		// 默认等待至少一分钟
		log.Println("Rate limited, waiting 1 minute")
		time.Sleep(time.Minute)
		return fmt.Errorf("rate limited")
	}
	return nil
}

func fetchJSON(url string, target interface{}) error {
	resp, err := makeRequest(url)
	if err != nil {
		return fmt.Errorf("request failed for URL %s: %w", url, err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("Error closing response body for URL %s: %v", url, closeErr)
		}
	}()

	// 处理速率限制
	if err := handleRateLimit(resp); err != nil {
		return fmt.Errorf("rate limited for URL %s: %w", url, err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP error %d for URL %s", resp.StatusCode, url)
	}

	if err := json.NewDecoder(resp.Body).Decode(target); err != nil {
		return fmt.Errorf("JSON decode failed for URL %s: %w", url, err)
	}

	return nil
}

func getRepoInfo(repoURL string) (RepoInfo, error) {
	info := RepoInfo{}

	parsedURL, err := url.Parse(repoURL)
	if err != nil {
		return info, err
	}

	pathParts := strings.Split(strings.Trim(parsedURL.Path, "/"), "/")
	if len(pathParts) != 2 {
		return info, fmt.Errorf("invalid repo URL format: %s", repoURL)
	}

	owner, repo := pathParts[0], pathParts[1]

	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s", owner, repo)
	var repoData struct {
		StargazersCount int    `json:"stargazers_count"`
		UpdatedAt       string `json:"updated_at"`
	}

	if err := fetchJSON(apiURL, &repoData); err != nil {
		return info, err
	}

	info.Stars = repoData.StargazersCount
	info.UpdatedAt = repoData.UpdatedAt

	apiURL = fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/metadata.yaml", owner, repo)
	var fileData struct {
		Content string `json:"content"`
	}

	if err := fetchJSON(apiURL, &fileData); err == nil {
		content, err := base64.StdEncoding.DecodeString(fileData.Content)
		if err == nil {
			versionRegex := regexp.MustCompile(`(?m)^version:\s*(.*)`)
			if match := versionRegex.FindStringSubmatch(string(content)); len(match) > 1 {
				versionLine := strings.TrimSpace(match[1])
				versionPatternRegex := regexp.MustCompile(`(v?\d+(?:\.\d+)+)`)
				if versionMatch := versionPatternRegex.FindStringSubmatch(versionLine); len(versionMatch) > 1 {
					info.Version = versionMatch[1]
				}
			}
		}
	}

	return info, nil
}

func enrichPluginsData(pluginsData map[string]PluginInfo) map[string]PluginInfo {
	result := make(map[string]PluginInfo)

	for key, plugin := range pluginsData {
		// 确保 Tags 不为 null
		if plugin.Tags == nil {
			plugin.Tags = []string{}
		}
		result[key] = plugin
	}

	semaphore := make(chan struct{}, MaxGoroutines)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for key, plugin := range result {
		if plugin.Repo == "" {
			continue
		}

		wg.Add(1)
		go func(key string, plugin PluginInfo) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			repoInfo, err := getRepoInfo(plugin.Repo)
			if err != nil {
				log.Printf("Error fetching repo info for %s: %v", plugin.Repo, err)
				return
			}

			mu.Lock()
			plugin.Stars = repoInfo.Stars
			plugin.UpdatedAt = repoInfo.UpdatedAt
			if repoInfo.Version != "" {
				plugin.Version = repoInfo.Version
			}
			result[key] = plugin
			mu.Unlock()
		}(key, plugin)
	}

	wg.Wait()
	return result
}

func fetchReleases() (json.RawMessage, error) {
	var rawData json.RawMessage
	if err := fetchJSON("https://api.github.com/repos/AstrBotDevs/AstrBot/releases", &rawData); err != nil {
		return nil, err
	}

	return rawData, nil
}

func fetchPlugins() (map[string]PluginInfo, error) {
	var fileData struct {
		Content string `json:"content"`
	}

	if err := fetchJSON("https://api.github.com/repos/AstrBotDevs/AstrBot_Plugins_Collection/contents/plugins.json", &fileData); err != nil {
		log.Printf("Failed to fetch plugins JSON: %v", err)
		return nil, err
	}

	content, err := base64.StdEncoding.DecodeString(fileData.Content)
	if err != nil {
		log.Printf("Failed to decode base64 content: %v", err)
		return nil, err
	}

	var pluginsData map[string]PluginInfo
	if err := json.Unmarshal(content, &pluginsData); err != nil {
		log.Printf("Failed to unmarshal plugins JSON: %v", err)
		log.Printf("Raw content: %s", string(content))
		return nil, err
	}

	return enrichPluginsData(pluginsData), nil
}

func updateCache() {
	log.Println("Starting cache update...")

	var wg sync.WaitGroup
	var newReleases json.RawMessage
	var newPlugins map[string]PluginInfo
	var releaseErr, pluginErr error

	// 获取发行信息
	wg.Add(1)
	go func() {
		defer wg.Done()
		newReleases, releaseErr = fetchReleases()
	}()

	// 获取插件
	wg.Add(1)
	go func() {
		defer wg.Done()
		newPlugins, pluginErr = fetchPlugins()
	}()

	wg.Wait()

	// 更新缓存
	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	hasUpdates := false
	if releaseErr == nil {
		cachedData.Releases = newReleases
		hasUpdates = true
		log.Println("Releases updated successfully")
	} else {
		log.Printf("Failed to update releases: %v", releaseErr)
	}

	if pluginErr == nil {
		cachedData.Plugins = newPlugins
		hasUpdates = true
		log.Println("Plugins updated successfully")
	} else {
		log.Printf("Failed to update plugins: %v", pluginErr)
	}

	if hasUpdates {
		cachedData.LastSync = time.Now()
		log.Println("Cache updated successfully")
	}
}

func getCachedData() APIData {
	cacheMutex.RLock()
	defer cacheMutex.RUnlock()
	return cachedData
}

func main() {
	if GithubToken == "" {
		log.Println("Warning: GITHUB_TOKEN not set. API rate limits will apply.")
	}

	// 初始化缓存
	cacheMutex.Lock()
	cachedData = APIData{
		Releases: json.RawMessage("[]"),
		Plugins:  make(map[string]PluginInfo),
		LastSync: time.Now(),
	}
	cacheMutex.Unlock()

	log.Println("Initializing cache...")
	updateCache()

	log.Printf("Starting AstrBot API with %d minute refresh interval", RefreshMinutes)

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())

	// CORS
	r.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	// 设置路由
	r.GET("/astrbot/releases", func(c *gin.Context) {
		data := getCachedData()
		c.Header("Content-Type", "application/json")
		c.Data(http.StatusOK, "application/json", data.Releases)
	})

	r.GET("/astrbot/plugins", func(c *gin.Context) {
		data := getCachedData()
		c.JSON(http.StatusOK, data.Plugins)
	})

	r.GET("/health", func(c *gin.Context) {
		data := getCachedData()
		c.JSON(http.StatusOK, gin.H{
			"status":    "healthy",
			"last_sync": data.LastSync,
		})
	})

	// 定时刷新缓存
	go func() {
		ticker := time.NewTicker(time.Duration(RefreshMinutes) * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			updateCache()
		}
	}()

	log.Printf("Server starting on port %s", RunPort)
	log.Fatal(r.Run(":" + RunPort))
}
