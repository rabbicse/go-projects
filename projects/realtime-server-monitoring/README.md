# Real-Time System Monitoring with Golang and HTMX

This project is a real-time system monitoring dashboard built using **Golang**, **HTMX**, and **WebSockets**. It was inspired by and extended from the [go-htmx-websockets-example](https://github.com/sigrdrifa/go-htmx-websockets-example) repository.

## 🚀 Features

- 📊 Real-time system metrics (CPU, Memory, Disk, etc.)
- ⚡ WebSocket-powered updates using HTMX's `hx-ws`
- 🧹 Modular and extensible codebase
- 🌐 Lightweight frontend with HTMX and minimal JavaScript
- 🔁 Background metrics polling using Go routines

## 📦 Tech Stack

- **Backend**: Go (Golang)
- **Frontend**: HTML, HTMX
- **Communication**: WebSocket via Gorilla/WebSocket
- **System Metrics**: `gopsutil` (or similar Go library)

## 📸 Screenshot

![realtime-monitoring-system](https://github.com/rabbicse/go-projects/blob/main/projects/realtime-server-monitoring/screenshots/realtime-system-monitor.png)

## 📁 Directory Structure

```
.
├── main.go               # Entry point of the application
├── handlers.go           # WebSocket and HTTP handler logic
├── templates/            # HTML templates with HTMX integration
│   └── index.html
├── static/               # Static files (CSS, JS if any)
├── go.mod / go.sum       # Go modules
└── README.md             # This file
```

## ⚙️ Setup Instructions

### 1. Clone the repository

```bash
git clone https://github.com/rabbicse/go-projects.git
cd projects/realtime-server-monitoring
```

### 2. Install Dependencies

```bash
go mod tidy
```

### 3. Run the Application

```bash
go run .
```

### 4. Open in Browser

Visit: [http://localhost:8080](http://localhost:8080)

## 📡 How It Works

- HTMX initiates a WebSocket connection with `hx-ws="connect:/ws"`
- The Go server streams real-time system stats via WebSocket
- HTMX auto-updates DOM elements as messages are received
- All updates are seamless and reactive without a full page reload

## 🛠️ Extending It

You can add more metrics like:
- Network I/O
- Process list
- Service health checks
- Remote system monitoring with agent-based model

## 🧚 Example System Metrics Code Snippet

```go
import "github.com/shirou/gopsutil/cpu"

cpuPercent, _ := cpu.Percent(0, false)
```

## 📄 License

MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Credits

- [sigrdrifa/go-htmx-websockets-example](https://github.com/sigrdrifa/go-htmx-websockets-example)

