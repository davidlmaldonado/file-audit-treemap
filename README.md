# file-audit-treemap

File-level storage audit tooling for large-scale filesystems. Generates interactive HTML treemap dashboards from `find(1)` scan data — designed for petabyte-scale storage with 50M+ files.

## What It Does

Scans all files under a mount point, captures size/atime/mtime, and builds a self-contained HTML dashboard with:

- **Treemap navigation** — drill down through the directory hierarchy by clicking
- **Access age analysis** (atime) — identifies data not accessed in 90d, 1y, 2y, 3y, 4y+
- **Modification age analysis** (mtime) — identifies unmodified data by the same tiers
- **File type breakdown** — top extensions by consumed space
- **Largest file identification** — files >100 MB surfaced per directory
- **Duplicate detection** — same filename + size across different directories (≥1 MiB)
- **CSV export** — all metrics exportable from the dashboard

## Architecture

```
file_scan.sh
  │
  ├─ Phase 1: parallel find(1) scans ──▶ *_files.tsv (per top-level directory)
  │    └─ auto-splits large dirs (>50 subdirs) into throttled parallel sub-finds
  │
  ├─ Phase 2: summary (file counts per volume)
  │
  └─ Phase 3: file_audit_builder.py ──▶ file_audit.html (self-contained dashboard)
       └─ optional: duplicates.html (standalone duplicate report)
```

## Usage

```bash
# Edit BASEPATH in file_scan.sh to match your mount point, then:
./scripts/file_scan.sh

# Or specify an output path:
./scripts/file_scan.sh /var/www/html/file_audit.html

# Python builder standalone (after scans exist):
python3 scripts/file_audit_builder.py /path/to/scan_dir --output /var/www/html/audit.html
```

### Cron (weekly, Sunday 3am)

```cron
0 3 * * 0 /path/to/scripts/file_scan.sh /path/to/output/file_audit.html >> /tmp/file_scan.log 2>&1
```

## Configuration

### file_scan.sh

| Variable | Default | Description |
|---|---|---|
| `BASEPATH` | `/your/mount` | Root directory to scan |
| `OUTDIR` | `./scans/file_scan_YYYYMMDD/` | Where TSV scan files are written |
| `SPLIT_THRESHOLD` | `50` | Directories with more subdirs than this get parallel sub-finds |
| `MAX_PARALLEL` | `8` | Max concurrent find processes for split directories |

### file_audit_builder.py

| Constant | Default | Description |
|---|---|---|
| `BASE_PATH` | `/your/mount` | Must match what `file_scan.sh` scanned |
| `ROOT_LABEL` | `storage/volume` | Label shown at treemap root |
| `TITLE` | `Storage/Volume` | Dashboard page title |
| `DUPE_MIN_SIZE` | `1 MiB` | Minimum file size for duplicate detection |
| `DUPE_TOP_N` | `50` | Top N duplicate sets shown in report |

CLI options:

```
python3 file_audit_builder.py <scan_dir> [--output <html>] [--parallel <N>]
```

## Performance

Optimized for large-scale scans:

- 8 MB buffered I/O reads in the Python parser
- Direct integer date parsing (no `strptime` overhead)
- Multiprocessing for parallel TSV parsing across volumes
- Progress reporting every 5M lines
- UUID directory detection — directories with 100+ UUID-named subdirs are automatically bucketed by size tier to keep the treemap navigable

## Requirements

- Bash 4+
- Python 3.6+ (standard library only — no pip dependencies)
- `find` with `-printf` support (GNU findutils)

## License

MIT
