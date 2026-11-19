# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Zoraxy plugin that blocks incoming connections whose IP is listed in the [Data-Shield IPv4 Blocklist](https://github.com/duggytuxy/Data-Shield_IPv4_Blocklist) (~100k IPs, updated every 6 hours).

The plugin integrates with [Zoraxy](https://zoraxy.aroz.org/) using **Dynamic Capture mode**: Zoraxy calls `/sniff` for every request, and the plugin returns accept (block) or skip (allow) based on a fast in-memory hash set lookup.

## Build & Test

```bash
go build -o datashield-blocklist .          # Build the plugin binary
./datashield-blocklist -introspect          # Verify plugin metadata JSON
go vet ./...                                # Lint
```

To install into Zoraxy, place the compiled binary in Zoraxy's `plugins/datashield-blocklist/` directory.

## Architecture

```
main.go                   # Plugin entry point, HTTP server, blocklist refresh goroutine
mod/zoraxy_plugin/        # Zoraxy plugin library (copied verbatim from Zoraxy source)
ui/index.html             # Plugin UI (embedded via //go:embed ui)
```

### How the plugin works

1. On startup: `plugin.ServeAndRecvSpec` handles `-introspect` (prints JSON + exits) or `-configure` (receives port from Zoraxy).
2. The HTTP server starts on `127.0.0.1:<port>` with three registered groups:
   - `/sniff/` — Dynamic sniff handler (called by Zoraxy for every request): extracts `RemoteAddr`, skips IPv6 and private IPs, does a `RLock` lookup on both the auto-refreshed blocklist and the manual blocklist, returns `SniffResultAccept` to block or `SniffResultSkip` to pass.
   - `/block/` — Dynamic capture handler: increments `blockedCount`, writes HTTP 403.
   - `/ui/` — Embedded web UI with the following JSON API endpoints:
     - `GET /ui/api/status` — returns `loaded`, `ip_count`, `last_updated`, `blocked_count`, `manual_ips`
     - `POST /ui/api/refresh` — triggers an async blocklist re-download
     - `GET /ui/api/add-ip?ip=<ipv4>` — adds an IPv4 address to the manual blocklist
     - `GET /ui/api/remove-ip?ip=<ipv4>` — removes an IP from the manual blocklist
3. A background goroutine refreshes the auto blocklist every 6 hours. On failure, the existing map is preserved.

### Key design choices

- **Two separate `map[string]struct{}`**: `blocklist` (auto-refreshed from Data-Shield) and `manualBlocklist` (user-managed), each protected by its own `sync.RWMutex`. O(1) IP lookup, `blocklist` pre-allocated with capacity 110000.
- **`atomic.Int64`** for `blockedCount` and `ipCount`: lock-free counters.
- Private/loopback/link-local CIDRs are parsed once at `init()` and checked before every blocklist lookup.
- IPv6 addresses pass through without lookup (the Data-Shield list is IPv4-only).
- Manual blocklist lives only in memory — it resets on plugin restart.

### Zoraxy plugin library

The files in `mod/zoraxy_plugin/` are copied verbatim from `github.com/tobychui/zoraxy/src/mod/plugins/zoraxy_plugin`. To update them, replace those files with the latest version from the Zoraxy repo and rebuild.

### Blocklist source

`blocklistURL` in `main.go` points to the full list (`prod_data-shield_ipv4_blocklist.txt`, ~100k IPs) fetched from the GitHub raw URL. Upstream also publishes split lists (`prod_aa-data-shield_ipv4_blocklist.txt` … `prod_ad-…`).
