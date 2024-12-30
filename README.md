# SSH Monitor

A lightweight SSH monitoring service that tracks login attempts and sends notifications to Discord.

## Installation

1. Build the binary:
   ```bash
   go build -o main main.go
   ```

2. Edit the systemd service file:
   ```bash
   # Copy the service file
   sudo cp better-monitor.service /etc/systemd/system/

   # Reload systemd
   sudo systemctl daemon-reload

   # Enable and start the service
   sudo systemctl enable better-monitor
   sudo systemctl start better-monitor
   ```

## Usage

### Service Management

```bash
# Check service status
sudo systemctl status better-monitor

# View logs
sudo journalctl -u better-monitor -f

# Restart service
sudo systemctl restart better-monitor

# Stop service
sudo systemctl stop better-monitor
```

### Log Files

- **Service logs**: `/var/log/better_monitor.log`
- **System logs**: `journalctl -u better-monitor`

## Configuration

The service monitors SSH activity and:
- Tracks attempts by subnet (e.g., `192.168.1.0/24`)
- Blocks subnets after 5 attempts per minute
- Sends notifications to Discord for:
  - Service start
  - SSH activity
  - Successful logins
  - Subnet blocks

## Troubleshooting

1. Check service status:
   ```bash
   sudo systemctl status better-monitor
   ```

2. Common issues:
   - If the service fails to start, check the webhook URL in the service file.
   - Ensure proper permissions for the log file.
   - Verify network connectivity for Discord notifications.