<h1 align="center">dazhbog</h1>

<h5 align="center">A high-performance, embedded-storage Lumina server for IDA Pro 7.2+</h5>

<br />

`dazhbog` is a fast, self-contained Lumina protocol server for storing and retrieving function signatures in IDA Pro. It uses embedded sled databases for both segments and indexing, requires zero external dependencies, and supports optional upstream forwarding to multiple Lumina servers with priority-based fallback.

---------------

<h3 align=center>Public dazhbog server</h3>

<div align=center>Supports both TLS and plaintext connections<br/>No special configuration required</div>

<h3 align=center><i>host</i>: ida.int.mov<br/><i>port</i>: 1234</h3>
<h3 align=center><i>user</i>: guest<br/><i>pass</i>: guest</h3>

---------------

### Installation

```bash
cargo build --release
./target/release/dazhbog config.toml
```

### Quick Start

```bash
# Start the server with default config
./dazhbog config.toml

# Or use the help flag
./dazhbog --help

# Configure IDA Pro >= 8.1 if TLS is NOT enabled
export LUMINA_TLS=false
./ida64
```

### Features

*   **Embedded Storage:** Uses sled embedded databases for both segment storage and indexing—no external database required
*   **Full Lumina Protocol Support:** Compatible with IDA Pro 7.2+ (protocol versions 0-6)
*   **Sled-Backed Index:** Persistent key-value index with automatic recovery and efficient lookups
*   **Append-Only Segments:** Immutable segment storage with CRC32C integrity validation and backward compatibility
*   **Function History:** Complete revision history via `prev_addr` linked lists
*   **Upstream Forwarding:** Multi-server upstream support with priority-based fallback for cache-miss scenarios
*   **HTTP Metrics:** Prometheus-compatible metrics endpoint at `/metrics`
*   **TLS Support:** Optional TLS with configurable certificate validation
*   **Automatic Recovery:** Index rebuilds from segments on startup; automatic migration from legacy storage formats
*   **Deduplication:** Optional startup deduplication to remove redundant records and reclaim space

### Architecture

`dazhbog` is built around three core components:

1.  **Storage Engine** - Sled-backed append-only segments with persistent index
2.  **RPC Server** - Lumina protocol TCP server with TLS support and multi-protocol handshake detection
3.  **HTTP Server** - Metrics and monitoring interface
4.  **Upstream Forwarding** - Optional proxy layer with priority-based multi-server support

### Storage Engine

The storage engine uses **sled** (an embedded key-value database) for both segment storage and indexing.

#### Segments (sled-backed)

*   Segments are stored as sled trees named `seg.00001`, `seg.00002`, etc.
*   Keys are 8-byte big-endian offsets for lexicographic ordering
*   Values are complete serialized records (header + body)
*   Default segment capacity: 1 GB (configurable)
*   Automatic segment rotation when capacity is reached
*   Legacy `.dat` files are automatically migrated to sled on first startup

#### Record Format

```
[MAGIC:4] [LEN:4] [CRC:4] [KEY_LO:8] [KEY_HI:8] [TIMESTAMP:8] [PREV_ADDR:8]
[LEN_BYTES:4] [POPULARITY:4] [NAME_LEN:2] [DATA_LEN:4] [FLAGS:1] [PAD:5]
[NAME:variable] [DATA:variable]
```

*   **Magic:** `0x4C4D4E31` (constant identifier)
*   **CRC:** CRC32C checksum over the body (legacy polynomial supported for backward compatibility)
*   **Key:** 128-bit function identifier (MD5 hash of function bytes)
*   **Prev_Addr:** 64-bit pointer to previous version (forms linked list for history)
*   **Flags:** Bit 0 = tombstone (deleted), remaining bits reserved

#### Index (sled-backed)

*   Persistent sled tree mapping 128-bit keys → 64-bit addresses
*   Address encoding: `[seg_id:16 | offset:47 | flags:1]`
*   Atomic upsert operations with `fetch_and_update`
*   Automatic rebuild from segments if empty (on first startup)
*   Legacy index files (`wal.dat`, `sst.*.ldb`) automatically migrated to `.legacy_index_*` backup

#### History Tracking

Each record's `prev_addr` field points to the previous version:
```
Index → Latest (v3) → Older (v2) → Oldest (v1) → NULL
```

History queries traverse this chain up to `lumina.get_history_limit`.

#### Tombstones

Deletions write a tombstone record with `flags & 0x01 = 1`. The index points to the tombstone, which links to previous versions, preserving history.

### Protocol Support

`dazhbog` implements full compatibility with IDA Pro's Lumina protocol:

**Supported Protocol Versions:**
*   Versions 0-6 (IDA Pro 7.2 through 9.0+)
*   Automatic detection of protocol version from hello message

**Message Types:**
*   `0x0d` - Lumina Hello (legacy)
*   `0x01` - New-style Hello
*   `0x0e` - PullMetadata (query functions)
*   `0x0f` - PullResult (query response)
*   `0x10` - PushMetadata (store functions)
*   `0x18` - DelHistory (delete functions, if enabled)
*   `0x2f` - GetFuncHistories (retrieve version history)
*   `0x0b` - Fail (error response)
*   `0x31` - HelloResult (version 5+ handshake response)

**Frame Format:**
```
[LENGTH:4 BE] [TYPE:1] [PAYLOAD:variable]
```

**Authentication:**
*   Username must be `guest` (hardcoded)
*   Password ignored
*   License validation bypassed in guest mode

### Upstream Forwarding

`dazhbog` can act as a caching proxy by forwarding cache misses to upstream Lumina servers:

**Multi-Server Support:**
*   Configure multiple upstream servers with priority levels
*   Lower priority number = higher priority (queried first)
*   Servers queried in priority order until all functions found
*   Each server can have independent TLS, timeout, and batch size settings

**Configuration Example:**
```toml
# Primary upstream (priority 0 = highest)
upstream.0.enabled = true
upstream.0.priority = 0
upstream.0.host = "lumina.hex-rays.com"
upstream.0.port = 443
upstream.0.use_tls = true
upstream.0.insecure_no_verify = true
upstream.0.hello_protocol_version = 6
upstream.0.license_path = "license.hexlic"
upstream.0.timeout_ms = 8000
upstream.0.batch_max = 131072

# Secondary upstream (priority 1)
upstream.1.enabled = true
upstream.1.priority = 1
upstream.1.host = "backup.lumina.server"
upstream.1.port = 1235
# ... additional settings
```

**Behavior:**
1.  Client queries dazhbog for function metadata
2.  If found locally, return immediately
3.  If not found, forward to upstream(s) in priority order
4.  Cache fetched results locally
5.  Return merged results to client

**License Support:**
*   Upstream connections can use license files (`.hexlic` format)
*   License ID automatically parsed from JSON and sent in hello handshake
*   Guest mode supported for license-free upstreams

### Configuration

Run `./dazhbog --help` for a complete list of configuration options.

**Example `config.toml`:**

```toml
# Connection and resource limits
limits.hello_timeout_ms = 3000
limits.command_timeout_ms = 15000
limits.max_active_conns = 2048
limits.max_pull_items = 524288
limits.max_push_items = 524288
limits.per_connection_inflight_bytes = 33554432  # 32 MB
limits.global_inflight_bytes = 536870912         # 512 MB

# Storage engine configuration
engine.data_dir = "data"
engine.segment_bytes = 1073741824  # 1 GB per segment
engine.shard_count = 64
engine.index_capacity = 1073741824
engine.deduplicate_on_startup = false  # Set true to deduplicate on startup (slow)
engine.index_memtable_max_entries = 200000
engine.index_block_entries = 128
engine.index_level0_compact_trigger = 8

# Lumina protocol server
lumina.bind_addr = "0.0.0.0:1234"
lumina.server_name = "dazhbog"
lumina.allow_deletes = false
lumina.get_history_limit = 32  # Max history versions to return (0 = disabled)
lumina.use_tls = false

# Upstream forwarding (optional)
upstream.0.enabled = true
upstream.0.priority = 0
upstream.0.host = "lumina.hex-rays.com"
upstream.0.port = 443
upstream.0.use_tls = true
upstream.0.insecure_no_verify = true
upstream.0.hello_protocol_version = 6
upstream.0.license_path = "license.hexlic"
upstream.0.timeout_ms = 8000
upstream.0.batch_max = 131072

# HTTP metrics server
http.bind_addr = "0.0.0.0:8080"
```

### IDA Pro Configuration

#### IDA Pro 8.1+

If your dazhbog server does NOT use TLS:

```bash
# Linux/macOS
export LUMINA_TLS=false
./ida64

# Windows
set LUMINA_TLS=false
ida64.exe
```

Then in IDA: **Options → General → Lumina** → "Use a private server"
*   Host: your server IP/hostname
*   Port: 1234 (or your configured port)
*   Username: `guest`
*   Password: `guest`

#### IDA Pro 7.2 - 8.0

Edit `cfg/ida.cfg`:

```c
LUMINA_HOST = "your.server.ip";
LUMINA_PORT = 1234;
LUMINA_TLS = NO;  // or YES if using TLS
```

### Performance

**Write Performance:**
*   Sled-backed append: thousands of functions/second
*   Atomic index updates via sled's `fetch_and_update`
*   Automatic segment rotation when capacity reached

**Read Performance:**
*   Function lookup: single sled tree query (microseconds)
*   History traversal: follows `prev_addr` chain with sequential sled reads
*   Batch queries scale linearly with request size

**Memory Usage:**
*   Sled cache: configurable (default 64-128 MB)
*   Index is persistent; no full in-memory index required
*   Memory budget enforcement via per-connection and global limits

**Disk Usage:**
*   ~200-500 bytes per function record
*   Sled overhead: ~10-20% for tree structure
*   History preserved via linked records
*   Deduplication can reclaim 20-50% space in redundant databases

### Recovery & Data Integrity

**Crash Recovery:**
*   Sled provides ACID guarantees with automatic recovery
*   If index is empty on startup, automatically rebuilt from segments
*   Corrupt records detected via CRC32C and skipped during rebuild
*   Legacy storage formats (`.dat` files, old index files) automatically migrated

**Rebuild Process:**
1.  Scan all segment trees in sled database
2.  For each record: validate magic, CRC32C, and structure
3.  Upsert valid records into index (tombstones processed correctly)
4.  Log progress and corrupt record count

**Data Integrity:**
*   CRC32C checksums on every record body
*   Backward-compatible CRC validation (supports legacy polynomial)
*   Sled ensures atomic writes and durability
*   No partial records possible due to sled's transaction model

### Monitoring

The HTTP server exposes Prometheus-compatible metrics at `http://localhost:8080/metrics`:

**Available Metrics:**
*   `dazhbog_pulls_total` - Number of functions successfully pulled
*   `dazhbog_pushes_total` - Number of functions pushed
*   `dazhbog_new_funcs_total` - New unique functions inserted
*   `dazhbog_queried_funcs_total` - Total function keys queried
*   `dazhbog_active_connections` - Active RPC connections
*   `dazhbog_lumina_v0_4` - Protocol version 0-4 handshakes
*   `dazhbog_lumina_v5p` - Protocol version 5+ handshakes
*   `dazhbog_errors_total` - Total errors
*   `dazhbog_timeouts_total` - Connection timeouts
*   `dazhbog_upstream_requests_total` - Upstream batch requests
*   `dazhbog_upstream_fetched_total` - Functions fetched from upstream
*   `dazhbog_upstream_errors_total` - Upstream connection errors
*   `dazhbog_index_overflows_total` - Index insertion failures
*   `dazhbog_append_failures_total` - Database append failures
*   `dazhbog_decoder_rejects_total` - Protocol decoder rejections

### Additional Tools

**Recovery Tool:**
```bash
./target/release/recover config.toml
```
Manually rebuilds the index from segments. Useful for debugging or recovery scenarios.

### Notes

*   **Etymology:** "dazhbog" (Дажьбог) is a Slavic sun deity
*   **Storage:** Uses sled embedded database (pure Rust, no C dependencies)
*   **Compatibility:** Full support for IDA Pro 7.2+ (Lumina protocol versions 0-6)
*   **Authentication:** Username must be `guest`; no password validation (designed for trusted networks)
*   **Migration:** Automatically migrates legacy `.dat` segment files and old index formats
*   **Startup Time:** Index rebuild scales with database size (~1 second per 1M functions)
*   **Deduplication:** Optional `deduplicate_on_startup` removes duplicate records but requires full rewrite (slow on large databases)

### License

MIT License

Copyright (c) 2025 Kenan Sulayman

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
