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

### Building from Source

1. **Install build dependencies**:
   ```bash
   sudo apt-get install build-essential debhelper ruby
   ```

2. **Build the package**:
   ```bash
   cd /home/sources/godaddy_ip_updater_rb
   dpkg-buildpackage -b
   ```

3. **Install the package**:
   ```bash
   sudo dpkg -i ../godaddy-ip-updater_1.0.0-1_all.deb
   ```

### Manual Installation

If you prefer to install manually:

1. Copy the script:
   ```bash
   sudo install -m 755 godaddy_ip_updater.rb /usr/sbin/godaddy-ip-updater
   ```

2. Copy systemd files:
   ```bash
   sudo install -m 644 godaddy-ip-updater.service /lib/systemd/system/
   sudo install -m 644 godaddy-ip-updater.timer /lib/systemd/system/
   sudo systemctl daemon-reload
   ```

3. Create config directory:
   ```bash
   sudo mkdir -p /etc/godaddy-ip-updater
   ```

## Configuration

After installation, configure the service:

1. **Edit the configuration file**:
   ```bash
   sudo cp /etc/godaddy-ip-updater/config.default /etc/godaddy-ip-updater/config
   sudo chmod 600 /etc/godaddy-ip-updater/config
   sudo nano /etc/godaddy-ip-updater/config
   ```

2. **Set your credentials** (required):
   ```bash
   GODADDY_API_KEY=your_api_key_here
   GODADDY_API_SECRET=your_api_secret_here
   GODADDY_DOMAIN=example.com
   ```

3. **Optional settings**:
   ```bash
   DNS_RECORD_NAME=@              # @ for root domain, or subdomain like "home"
   DNS_RECORD_TYPE=A              # Usually "A" for IPv4
   ```

## Usage

### Enable and Start the Service

After configuring, enable and start the systemd timer:

```bash
sudo systemctl enable --now godaddy-ip-updater.timer
```

The timer will trigger every 3 hours automatically.

### Service Management

**Check timer status**:
```bash
sudo systemctl status godaddy-ip-updater.timer
```

**Check service logs**:
```bash
sudo journalctl -u godaddy-ip-updater.service -f
```

**Manually trigger a check**:
```bash
sudo systemctl start godaddy-ip-updater.service
```

**Stop the timer**:
```bash
sudo systemctl stop godaddy-ip-updater.timer
sudo systemctl disable godaddy-ip-updater.timer
```

**View timer schedule**:
```bash
systemctl list-timers godaddy-ip-updater.timer
```

## Configuration Examples

### Update Root Domain (example.com)
```bash
GODADDY_DOMAIN=example.com
DNS_RECORD_NAME=@
```

### Update Subdomain (home.example.com)
```bash
GODADDY_DOMAIN=example.com
DNS_RECORD_NAME=home
```

### Change Check Interval

Edit `/lib/systemd/system/godaddy-ip-updater.timer` and modify the `OnUnitActiveSec` value:

```ini
OnUnitActiveSec=1h    # Check every hour
OnUnitActiveSec=6h    # Check every 6 hours
OnUnitActiveSec=30m   # Check every 30 minutes
```

Then reload:
```bash
sudo systemctl daemon-reload
sudo systemctl restart godaddy-ip-updater.timer
```

## How It Works

1. Systemd timer triggers the service every 3 hours
2. The service checks your external IP using multiple services (ipify.org, ifconfig.me, etc.)
3. Compares it with the last known IP stored in `/var/lib/godaddy-ip-updater/last_ip.txt`
4. If the IP changed, it uses the GoDaddy API to update your DNS record
5. Saves the new IP for future comparisons
6. Service exits and waits for the next timer trigger

## Troubleshooting

### "Configuration file not found"
Make sure `/etc/godaddy-ip-updater/config` exists and is readable:
```bash
sudo ls -la /etc/godaddy-ip-updater/config
sudo cat /etc/godaddy-ip-updater/config
```

### "Unable to determine external IP"
- Check your internet connection
- The IP check services might be temporarily unavailable
- Check logs: `sudo journalctl -u godaddy-ip-updater.service`

### "GoDaddy API error"
- Verify your API credentials in `/etc/godaddy-ip-updater/config` are correct
- Make sure you're using the **Production** API, not sandbox
- Check that your domain is managed by GoDaddy
- Verify the DNS record name and type are correct
- Check API response in logs: `sudo journalctl -u godaddy-ip-updater.service -n 50`

### Permission Errors
- Ensure `/var/lib/godaddy-ip-updater/` is writable by root (should be automatic)
- Check directory permissions: `ls -la /var/lib/godaddy-ip-updater/`

### Timer Not Running
- Check if timer is enabled: `systemctl is-enabled godaddy-ip-updater.timer`
- Check timer status: `systemctl status godaddy-ip-updater.timer`
- View next run time: `systemctl list-timers godaddy-ip-updater.timer`

## Security Notes

- The configuration file at `/etc/godaddy-ip-updater/config` should be readable only by root (mode 600)
- Never commit your API credentials to version control
- The script stores your last IP in `/var/lib/godaddy-ip-updater/last_ip.txt` (owned by root)
- Consider using a restricted API key with only DNS update permissions if possible
- Review systemd logs regularly: `sudo journalctl -u godaddy-ip-updater.service`

## Building Debian Package

To build the package for distribution:

```bash
cd /home/sources/godaddy_ip_updater_rb
dpkg-buildpackage -b
```

This will create a `.deb` file in the parent directory.

To modify the package version, edit `debian/changelog`:

```bash
dch -i  # Increment version
# or
dch -v 1.0.1-1 "Fixed configuration parsing"
```

## License

This script is provided as-is for personal use. Feel free to modify and adapt it to your needs.