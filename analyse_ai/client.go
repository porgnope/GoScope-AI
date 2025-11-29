package analyse_ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Config хранит настройки подключения
type Config struct {
	APIKey string
	Model  string
}

// Client - структура клиента Groq
type Client struct {
	config Config
	http   *http.Client
}

// NewClient создает новый экземпляр клиента
// Если apiKey пустой - будет ошибка при запросе
func NewClient(apiKey string) *Client {
	// Модель по умолчанию - быстрая Llama 3 70B
	return &Client{
		config: Config{
			APIKey: apiKey,
			Model:  "llama-3.3-70b-versatile",
		},
		http: &http.Client{Timeout: 30 * time.Second}, // Groq быстрый, 30 сек хватит
	}
}

// Структуры для Groq API (OpenAI-compatible)
type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model    string        `json:"model"`
	Messages []chatMessage `json:"messages"`
	Stream   bool          `json:"stream"`
}

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Error struct {
		Message string `json:"message"`
	} `json:"error"`
}

// Analyze отправляет текст на анализ в Groq
func (c *Client) Analyze(prompt string) (string, error) {
	if c.config.APIKey == "" {
		return "", fmt.Errorf("Groq API Key is missing! Please set it via config or flag")
	}

	reqBody := chatRequest{
		Model: c.config.Model,
		Messages: []chatMessage{
			{Role: "user", Content: prompt},
		},
		Stream: false,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("json error: %v", err)
	}

	// URL Groq API
	url := "https://api.groq.com/openai/v1/chat/completions"

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}

	// Важные заголовки
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.config.APIKey)

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("connection error: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API Error: Status %d - %s", resp.StatusCode, string(body))
	}

	var groqResp chatResponse
	if err := json.Unmarshal(body, &groqResp); err != nil {
		return "", fmt.Errorf("parsing error: %v", err)
	}

	if len(groqResp.Choices) == 0 {
		return "", fmt.Errorf("empty response from AI")
	}

	return strings.TrimSpace(groqResp.Choices[0].Message.Content), nil
}
