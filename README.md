# Failban

A lightweight fail2ban-like intrusion prevention system for OpenWrt routers.

## Overview

`failban` monitors system logs in real-time to detect failed authentication attempts and automatically blocks malicious IP addresses using nftables. It's specifically designed for resource-constrained OpenWrt environments.

## Features

- **Real-time log monitoring**: Watches system logs via `logread` for authentication failures
- **Protocol support**: SSH (Dropbear), HTTP (Luci/uhttpd), IKEv2/IPSec
- **Automatic blocking**: Uses nftables to drop traffic from offending IPs
- **Configurable thresholds**: Set custom ban times, retry limits, and detection windows
- **Temporary bans**: Automatically unban IPs after configured time period
- **Persistent ban list**: Maintains ban records across restarts
- **Low resource usage**: Minimal memory footprint suitable for embedded systems

## Requirements

- OpenWrt router with nftables support
- CMake 3.11 or higher (for building)
- OpenWrt SDK (for cross-compilation)
- `logread` utility (standard on OpenWrt)

## Building

### Compilation for OpenWrt

The build system automatically detects the `STAGING_DIR` environment variable (standard in OpenWrt SDK) to configure cross-compilation.

```bash
# Set STAGING_DIR (usually done automatically by OpenWrt SDK)
export STAGING_DIR=/path/to/openwrt-sdk/staging_dir

# Clone the repository
git clone https://github.com/yourusername/failban.git
cd failban

# Configure and build
cmake -B build
cmake --build build

# The executable will be in build/failban
```

> **Note**: If `STAGING_DIR` is not set, it will default to a native build for your current system.

## Configuration

Edit `/etc/failban.conf` to customize behavior:

```ini
# Logging verbosity (0 = quiet, 1 = verbose)
verbose = 0

# Ban duration in seconds (default: 3 days)
bantime = 259200

# Time window to detect failures (default: 1 hour)
findtime = 3600

# Maximum retry attempts before banning
maxretry = 4

# Ban list file location
banfile = /tmp/failban.lst

# nftables table and chain names
nfttable = fw4
nftchain = failban

# Regular expressions to match log entries
[proto_search]
ssh = dropbear.*Exit before auth
http = uhttpd.*luci: failed login on
ikev2 = ipsec.*(no IKE config found|sending NO_PROPOSAL_CHOSEN|received unsupported IKE version|deleting half open)

# Protocol and port mappings
[proto_ports]
ssh = tcp:22
http = tcp:80,tcp:443
ikev2 = udp:4500
```

### Configuration Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `verbose` | Enable verbose logging | `0` |
| `bantime` | How long to ban IPs (seconds) | `259200` (3 days) |
| `findtime` | Time window for failure detection (seconds) | `3600` (1 hour) |
| `maxretry` | Failed attempts before ban | `4` |
| `banfile` | Path to persistent ban list | `/tmp/failban.lst` |
| `nfttable` | nftables table name | `fw4` |
| `nftchain` | nftables chain name | `failban` |

## Installation on OpenWrt

1. Copy the compiled `failban` binary to your router:
   ```bash
   scp -O build/failban root@router:/usr/bin/
   ```

2. Copy the configuration file:
   ```bash
   scp -O conf/failban.conf root@router:/etc/
   ```

3. Copy the init script:
   ```bash
   scp -O init/failban root@router:/etc/init.d/
   ```

4. Set proper permissions:
   ```bash
   ssh root@router "chmod +x /usr/bin/failban"
   ssh root@router "chmod +x /etc/init.d/failban"
   ```

5. Enable and start the service:
   ```bash
   ssh root@router "service failban enable"
   ssh root@router "service failban start"
   ```


## Usage

### Starting failban

```bash
# Run in foreground
./failban

# Or as a daemon (use the init script)
service failban start
```

### Viewing Logs

```bash
# Check syslog for failban messages
logread | grep failban
```

### Checking Banned IPs

```bash
# View the ban list
cat /tmp/failban.lst

# View nftables rules
nft list chain inet fw4 failban
```

### Manually Unbanning an IP

To manually remove a ban, you can either:

1. Remove the entry from the ban list file and restart failban
2. Delete the nftables rule:
   ```bash
   nft --handle list chain inet fw4 failban
   nft delete rule inet fw4 failban handle <handle_number>
   ```

## How It Works

1. **Monitoring**: failban tails system logs via `logread -f`
2. **Pattern Matching**: Matches log lines against configured regex patterns
3. **IP Extraction**: Extracts IP addresses from matched log entries
4. **Threshold Detection**: Tracks failed attempts per IP within the time window
5. **Blocking**: Once threshold is exceeded, adds nftables drop rules
6. **Auto-unban**: Removes expired bans based on configured `bantime`

## Dependencies

The project uses [inih](https://github.com/benhoyt/inih) for INI file parsing. The library is automatically downloaded and built via CMake's FetchContent during compilation.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues.
