# Cloudflare IP Updater

![GitHub total downloads](https://img.shields.io/github/downloads/hardenedpenguin/cloudflare_ip_updater_rb/total?style=flat-square)

A Ruby-based Debian package that monitors your external IP address and automatically updates your Cloudflare DNS records when it changes. Uses systemd timer for scheduling.

## Features

- ✅ Checks external IP via systemd timer (configurable interval, default 3 hours)
- ✅ Automatically updates Cloudflare DNS when IP changes
- ✅ **Multi-record & multi-domain support** – update many DNS records across domains in one run
- ✅ **IPv4 (A) and IPv6 (AAAA) support** – keeps both record types in sync
- ✅ Supports root domain (@) and subdomains
- ✅ Auto-detects Zone ID and DNS Record ID if not provided
- ✅ Uses multiple IP check services for reliability (separate services for IPv4 and IPv6)
- ✅ Stores last known IPs (IPv4 and IPv6) to avoid unnecessary updates
- ✅ Systemd service integration with journal logging
- ✅ **Retry logic with exponential backoff** for transient failures
- ✅ **Rate limit handling** (429 responses with Retry-After)
- ✅ **Dry-run mode** (`--dry-run`) to test without making changes
- ✅ **Configurable check interval** via `CHECK_INTERVAL` and `--setup-timer`
- ✅ **Optional DNS propagation check** after updates (`VERIFY_DNS=1`)
- ✅ Uses only Ruby standard library (no gems required!)
- ✅ Proper Debian package structure

## Prerequisites

- Debian/Ubuntu system with systemd
- Ruby 2.0 or higher
- Cloudflare account with domain
- Cloudflare API token (see setup below)

## Getting Cloudflare API Token

1. Go to [Cloudflare API Tokens](https://dash.cloudflare.com/profile/api-tokens)
2. Click "Create Token"
3. Use the "Edit zone DNS" template, or create a custom token with:
   - **Permissions**: Zone:Zone:Read, Zone:DNS:Edit
   - **Zone Resources**: Include - Specific zone - [your domain]
4. Copy the generated API token

⚠️ **Important**: Save the token immediately - it won't be shown again!

## Installation

1. **Download and install the package**:
   ```bash
   cd /tmp
   wget https://github.com/hardenedpenguin/cloudflare_ip_updater_rb/releases/download/v1.0.0/cloudflare-ip-updater_1.0.0-1_all.deb
   sudo apt install ./cloudflare-ip-updater_1.0.0-1_all.deb
   ```

   The `apt install` command will automatically handle dependencies and install `ruby` and `systemd` if they are not already installed.

## Configuration

Edit the configuration file with your Cloudflare API token:

```bash
sudo nano /etc/cloudflare-ip-updater/config
```

### Multi-record mode (recommended)

Add one or more `RECORD` lines. Format: `RECORD=domain:record_name:type`

```ini
CLOUDFLARE_API_TOKEN=your_api_token_here

# Update root domain with both IPv4 and IPv6
RECORD=example.com:@:A
RECORD=example.com:@:AAAA

# Update subdomains
RECORD=example.com:home:A
RECORD=example.com:home:AAAA
RECORD=example.com:vpn:A

# Different domain
RECORD=other.com:server:A
```

### Legacy single-record mode

If no `RECORD` lines are present, the script uses the legacy format:

- `CLOUDFLARE_API_TOKEN` - Your Cloudflare API token (required)
- `DOMAIN` - Your domain name (e.g., example.com) (required)
- `DNS_RECORD_NAME` - DNS record name (@ for root, or subdomain like `home`)
- `DNS_RECORD_TYPE` - `A` (IPv4) or `AAAA` (IPv6)

### Optional settings

- `CHECK_INTERVAL` - Check interval in minutes (default: 180). After changing, run `sudo cloudflare-ip-updater --setup-timer`
- `RETRY_ATTEMPTS` - Retry attempts for API and IP checks (default: 3)
- `VERIFY_DNS` - Set to `1` to verify DNS propagation after each update (default: 0)

## Usage

Enable and start the service:

```bash
sudo systemctl enable cloudflare-ip-updater.service
sudo systemctl enable --now cloudflare-ip-updater.timer
```

The timer will trigger every 3 hours by default. To change the interval, set `CHECK_INTERVAL` in config (in minutes) and run:

```bash
sudo cloudflare-ip-updater --setup-timer
```

**Check status**: `sudo systemctl status cloudflare-ip-updater.timer`  
**View logs**: `sudo journalctl -u cloudflare-ip-updater.service -f`  
**Manual check**: `sudo systemctl start cloudflare-ip-updater.service`  
**Dry-run** (test without changes): `sudo cloudflare-ip-updater --dry-run`

## Troubleshooting

Check logs for errors: `sudo journalctl -u cloudflare-ip-updater.service`

Common issues:
- **Configuration file not found**: Ensure `/etc/cloudflare-ip-updater/config` exists
- **Unable to determine external IP**: Check internet connection and logs
- **Unable to determine external IPv6**: If you don't have IPv6 connectivity, remove AAAA records from your config. The script will continue to update A records.
- **Cloudflare API error**: Verify API token has correct permissions (Zone:Zone:Read, Zone:DNS:Edit)
- **Invalid RECORD format**: Use `domain:record_name:type` (e.g., `example.com:@:A`)
- **Timer not running**: Check status with `sudo systemctl status cloudflare-ip-updater.timer`
- **Change check interval**: Edit `CHECK_INTERVAL` in config, then run `sudo cloudflare-ip-updater --setup-timer`

## License

This script is provided as-is for personal use. Feel free to modify and adapt it to your needs.
