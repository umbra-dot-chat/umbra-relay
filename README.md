# Umbra Relay Server

A lightweight WebSocket relay server for Umbra P2P messaging. The relay provides:

- **Signaling relay** - Forwards WebRTC SDP offers/answers for peer connection establishment
- **Offline message queue** - Stores encrypted messages for offline peers (7-day TTL)
- **Single-scan friend adding** - QR code/link-based peer connections

All message payloads are end-to-end encrypted on the client side. The relay never sees plaintext content.

## Quick Start

### Option 1: Download Pre-built Binary

Download the latest release for your platform from the [Releases page](https://github.com/InfamousVague/Umbra/releases?q=relay):

- `umbra-relay-linux-x86_64` - Linux (64-bit)
- `umbra-relay-linux-aarch64` - Linux (ARM64)
- `umbra-relay-darwin-x86_64` - macOS (Intel)
- `umbra-relay-darwin-aarch64` - macOS (Apple Silicon)
- `umbra-relay-windows-x86_64.exe` - Windows (64-bit)

Make it executable and run:

```bash
chmod +x umbra-relay-linux-x86_64
./umbra-relay-linux-x86_64 --port 8080
```

### Option 2: Build from Source

Requires [Rust](https://rustup.rs/) 1.75 or later.

```bash
# Clone and build
git clone https://github.com/InfamousVague/Umbra.git
cd Umbra/packages/umbra-relay
cargo build --release

# Run
./target/release/umbra-relay --port 8080
```

### Option 3: Docker

```bash
# Build
docker build -t umbra-relay .

# Run
docker run -d -p 8080:8080 --name umbra-relay umbra-relay
```

Or use Docker Compose:

```bash
docker compose up -d
```

## Configuration

Configure via command-line arguments or environment variables:

| Argument | Environment Variable | Default | Description |
|----------|---------------------|---------|-------------|
| `--port` | `RELAY_PORT` | `8080` | Server port |
| `--region` | `RELAY_REGION` | `US East` | Region label for /info |
| `--location` | `RELAY_LOCATION` | `New York` | Location label for /info |
| `--max-offline` | `MAX_OFFLINE_MESSAGES` | `1000` | Max offline messages per user |
| `--offline-ttl` | `OFFLINE_TTL_DAYS` | `7` | Days to keep offline messages |
| `--session-ttl` | `SESSION_TTL_SECS` | `3600` | Session timeout (seconds) |
| `--cleanup-interval` | `CLEANUP_INTERVAL_SECS` | `300` | Cleanup interval (seconds) |

### Example

```bash
# Command line
./umbra-relay --port 8080 --region "Europe" --location "Frankfurt"

# Environment variables
RELAY_PORT=8080 RELAY_REGION="Europe" RELAY_LOCATION="Frankfurt" ./umbra-relay
```

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Health check - returns `{"status": "ok"}` |
| `GET /info` | Server info - region, location, online count |
| `GET /stats` | Statistics - clients, messages, sessions |
| `WS /ws` | WebSocket endpoint for clients |

## SSL/TLS Setup

For production, use a reverse proxy (nginx, Caddy) with SSL certificates.

### Nginx Example

```nginx
server {
    listen 443 ssl;
    server_name relay.example.com;

    ssl_certificate /etc/letsencrypt/live/relay.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/relay.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 86400;
    }
}
```

### Let's Encrypt (Certbot)

```bash
# Install certbot
apt install certbot python3-certbot-nginx

# Get certificate
certbot --nginx -d relay.example.com
```

## Adding to Umbra

Once your relay is running:

1. Open Umbra Settings > Network
2. Add your relay URL: `wss://relay.example.com/ws`
3. Toggle it on

Your relay will now be used for signaling and offline message delivery.

## System Requirements

- **Memory**: ~64MB minimum, 256MB recommended
- **CPU**: Minimal (handles thousands of concurrent connections)
- **Disk**: Minimal (data is in-memory, lost on restart)
- **Network**: Open port for WebSocket connections

## Systemd Service

Create `/etc/systemd/system/umbra-relay.service`:

```ini
[Unit]
Description=Umbra Relay Server
After=network.target

[Service]
Type=simple
User=umbra
ExecStart=/opt/umbra-relay/umbra-relay --port 8080 --region "Your Region" --location "Your City"
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl enable umbra-relay
sudo systemctl start umbra-relay
```

## License

MIT License - see LICENSE file for details.
