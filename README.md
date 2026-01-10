# GoDaddy IP Updater

A Ruby-based Debian package that monitors your external IP address and automatically updates your GoDaddy DNS records when it changes. Uses systemd timer for scheduling.

## Features

- ✅ Checks external IP every 3 hours via systemd timer
- ✅ Automatically updates GoDaddy DNS when IP changes
- ✅ Supports root domain (@) and subdomains
- ✅ Uses multiple IP check services for reliability
- ✅ Stores last known IP to avoid unnecessary updates
- ✅ Systemd service integration with journal logging
- ✅ Uses only Ruby standard library (no gems required!)
- ✅ Proper Debian package structure

## Prerequisites

- Debian/Ubuntu system with systemd
- Ruby 2.0 or higher
- GoDaddy domain with API access
- GoDaddy API credentials (see setup below)

## Getting GoDaddy API Credentials

1. Go to [GoDaddy Developer Portal](https://developer.godaddy.com/)
2. Sign in with your GoDaddy account
3. Click "Create New API Key"
4. Give it a name (e.g., "IP Updater")
5. Select **Production** environment (not OTE/Sandbox)
6. Copy the API Key and API Secret

⚠️ **Important**: Make sure to use the **Production** API, not the sandbox/test API!

## Installation

1. **Download and install the package**:
   ```bash
   cd /tmp
   wget https://github.com/hardenedpenguin/godaddy_ip_updater_rb/releases/download/v1.0.0/godaddy-ip-updater_1.0.0-1_all.deb
   sudo apt install ./godaddy-ip-updater_1.0.0-1_all.deb
   ```

   The `apt install` command will automatically handle dependencies and install `ruby` and `systemd` if they are not already installed.

## Configuration

Edit the configuration file with your GoDaddy API credentials:

```bash
sudo nano /etc/godaddy-ip-updater/config
```

Set your API credentials and domain:
- `GODADDY_API_KEY` - Your GoDaddy API key
- `GODADDY_API_SECRET` - Your GoDaddy API secret
- `GODADDY_DOMAIN` - Your domain name (e.g., example.com)
- `DNS_RECORD_NAME` - DNS record name (@ for root, or subdomain)
- `DNS_RECORD_TYPE` - DNS record type (usually A)

## Usage

Enable and start the service:

```bash
sudo systemctl enable godaddy-ip-updater.service
sudo systemctl enable --now godaddy-ip-updater.timer
```

The timer will trigger every 3 hours automatically.

**Check status**: `sudo systemctl status godaddy-ip-updater.timer`  
**View logs**: `sudo journalctl -u godaddy-ip-updater.service -f`  
**Manual check**: `sudo systemctl start godaddy-ip-updater.service`

## Troubleshooting

Check logs for errors: `sudo journalctl -u godaddy-ip-updater.service`

Common issues:
- **Configuration file not found**: Ensure `/etc/godaddy-ip-updater/config` exists
- **Unable to determine external IP**: Check internet connection and logs
- **GoDaddy API error**: Verify API credentials and that you're using Production API (not sandbox)
- **Timer not running**: Check status with `sudo systemctl status godaddy-ip-updater.timer`

## License

This script is provided as-is for personal use. Feel free to modify and adapt it to your needs.