# 🔭 GoScope AI

**Advanced Web Scanner & Reconnaissance Tool with AI Analysis**

[![Language](https://img.shields.io/badge/Lang-English-blue)](#english) [![Language](https://img.shields.io/badge/Язык-Русский-red)](#russian)

---

<a name="english"></a>
## 🇺🇸 English Description

**GoScope AI** is a high-performance, multi-mode web scanner written in Go. It combines fast concurrent scanning, headless browsing for SPA discovery (React, Vue, etc.), and **AI-powered vulnerability analysis** using **Llama 3.3** (via Groq Cloud) to filter noise and highlight real security risks.

Designed for penetration testers, bug bounty hunters, and security engineers who value speed, accuracy, and privacy.

### 🔥 Key Features

- **🚀 Fast & Concurrent:** Scans thousands of URLs in seconds with adjustable threading.
- **🧠 AI Security Analysis:** Uses **Llama 3.3 (70B)** to analyze HTTP responses.
  - *Smart Filtering:* Distinguishes public login pages (Low Risk) from exposed admin panels (High Risk).
  - *Context Aware:* Detects PII, API keys, and stack traces in response bodies.
  - *No Hallucinations:* Strict prompting prevents false positives.
- **🌐 SPA & Headless Support:**
  - Detects dynamic routes in React/Vue/Angular apps.
  - Headless browser mode captures XHR/Fetch requests invisible to static scanners.
- **🕷️ BFS Crawler:** Built-in crawler to explore nested paths.
- **📂 Clean Reports:** Generates professional Markdown reports sorted by risk level.

### 📦 Installation

#### Pre-requisites
- **Go 1.21+**
- **Chrome/Chromium** (required only for Headless mode)

#### Build from source

- git clone https://github.com/porgnope/goscope.git
- cd goscope
- go mod tidy
- go build -o goscope main.go



### 🚀 Usage

1.  **Run GoScope:**
    Simply execute the binary.
    ```
    ./goscope
    ```

2.  **Configure AI (Interactive):**
    During the scan, GoScope will ask if you want to perform AI Analysis.
    - If you choose **Yes (y)**, it will prompt you for your **Groq API Key**.
    - You can get a free key at [console.groq.com](https://console.groq.com).

### 🛠️ Scan Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| **Scan** | Standard HTTP fuzzer & crawler. | Fast recon, API discovery. |
| **Headless** | Uses a real browser to render pages. | SPA sites (React/Vue), finding DOM-based links. |
| **Combo** | Runs Scan + Headless sequentially. | Maximum coverage (takes longer). |

---

<a name="russian"></a>
## 🇷🇺 Описание на Русском

**GoScope AI** — это продвинутый веб-сканер, написанный на Go. Он объединяет высокую скорость сканирования, поддержку SPA-приложений (через headless-браузер) и **анализ уязвимостей с помощью ИИ** (Llama 3.3 через Groq Cloud) для фильтрации ложных срабатываний.

Создан для пентестеров, баг-хантеров и специалистов по ИБ, которым важна скорость и точность.

### 🔥 Основные возможности

- **🚀 Быстрое сканирование:** Многопоточный фаззинг тысяч URL за секунды.
- **🧠 ИИ-Анализ:** Использует **Llama 3.3 (70B)** для анализа ответов сервера.
  - *Умная фильтрация:* Отличает публичные страницы входа (Низкий риск) от открытых админок (Высокий риск).
  - *Понимание контекста:* Находит утечки данных (PII), ключи API и стектрейсы ошибок.
  - *Без галлюцинаций:* Специальный промпт минимизирует выдуманные уязвимости.
- **🌐 Поддержка SPA:**
  - Находит динамические маршруты в приложениях на React, Vue, Angular.
  - Headless-режим перехватывает скрытые запросы (XHR/Fetch).
- **🕷️ BFS Краулер:** Встроенный краулер для глубокого поиска вложенных путей.
- **📂 Понятные отчеты:** Генерирует красивые Markdown-отчеты с сортировкой по критичности.

### 📦 Установка

#### Требования
- **Go 1.21+**
- **Chrome/Chromium** (нужен только для режима Headless)

#### Сборка из исходников

- git clone https://github.com/porgnope/goscope.git
- cd goscope
- go mod tidy
- go build -o goscope main.go



### 🚀 Использование

1.  **Запустите GoScope:**
    Просто запустите скомпилированный файл.
    ```
    ./goscope
    ```

2.  **Настройка ИИ (Интерактивно):**
    В процессе работы программа спросит, хотите ли вы запустить AI-анализ.
    - Если выберете **Да (y)**, программа попросит ввести **Groq API Key**.
    - Получить бесплатный ключ можно на [console.groq.com](https://console.groq.com).


### 🛠️ Режимы сканирования

| Режим | Описание | Для чего использовать |
|-------|----------|-----------------------|
| **Scan** | Стандартный фаззинг и краулинг. | Быстрая разведка, поиск API. |
| **Headless** | Использует реальный браузер. | SPA сайты (React/Vue), поиск ссылок в DOM. |
| **Combo** | Запускает Scan + Headless последовательно. | Максимальное покрытие (дольше по времени). |

---

## ⚠️ Disclaimer
This tool is for **educational purposes and authorized security testing only**. Do not use it on targets you do not have permission to test. The author is not responsible for any misuse.

---
**Star ⭐ this repo if you find it useful!**
