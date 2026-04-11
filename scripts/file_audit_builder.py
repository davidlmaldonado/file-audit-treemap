#!/usr/bin/env python3
"""
file_audit_builder.py — Storage Volume file-level storage audit dashboard.

Generates an interactive HTML treemap dashboard from find(1) scan data, with:
  - Directory-level size rollups with drill-down navigation
  - Access age analysis (atime) and modification age analysis (mtime)
  - File type breakdown and largest file identification
  - Integrated duplicate file detection (same name + size)
  - CSV export of all metrics

Optimized for large scans (50M+ files):
  - 8 MB buffered I/O reads
  - Direct integer date parsing (no strptime overhead)
  - Progress reporting every 5M lines
  - Multiprocessing for parallel TSV parsing

Usage:
    python3 file_audit_builder.py <scan_dir> [--output <html_path>]

Expects <scan_dir> to contain *_files.tsv files produced by file_scan.sh.
Each TSV line: size_bytes<TAB>atime<TAB>mtime<TAB>full_path
"""

import json
import glob
import os
import re
import sys
import time
from collections import defaultdict
from datetime import datetime, date
from multiprocessing import Pool, cpu_count

# ─── Constants ──────────────────────────────────────────────────────────

BASE_PATH = "/mnt/storage"
ROOT_LABEL = "storage"
DISPLAY_LABEL = "storage"
TITLE = "Storage Audit"
DUPE_MIN_SIZE = 1024 * 1024     # 1 MiB minimum for duplicate detection
DUPE_TOP_N = 50                 # Top N duplicate sets in dashboard

AT_THRESHOLDS = [90, 365, 730, 1095, 1460]
AT_LABELS = ["< 90d", "90d-1y", "1-2y", "2-3y", "3-4y", "4y+"]

# ─── Utility functions ──────────────────────────────────────────────────

def atime_bucket(days):
    for i, t in enumerate(AT_THRESHOLDS):
        if days < t:
            return i
    return 5

def is_uuid(name):
    base = name.split('_')[0] if '_' in name else name
    return (len(base) == 36 and base[8:9] == '-' and
            base[13:14] == '-' and base[18:19] == '-')

def bytes_to_tib(b):
    return b / 1024 / 1024 / 1024 / 1024

def round_tib(b):
    tib = bytes_to_tib(b)
    return round(tib, 2) if tib >= 0.01 else round(tib, 4)

def fmt_size(b):
    if b >= 1024**4:
        return "{:.2f} TiB".format(b / 1024**4)
    if b >= 1024**3:
        return "{:.2f} GiB".format(b / 1024**3)
    if b >= 1024**2:
        return "{:.1f} MiB".format(b / 1024**2)
    if b >= 1024:
        return "{:.0f} KiB".format(b / 1024)
    return "{} B".format(b)

def pct_of(part, total):
    return part / total * 100 if total else 0

# ─── Node class ─────────────────────────────────────────────────────────

class Node:
    __slots__ = ['size', 'files', 'atime', 'mtime', 'exts', 'top_files', 'children']
    def __init__(self):
        self.size = 0
        self.files = 0
        self.atime = [0] * 6
        self.mtime = [0] * 6
        self.exts = {}
        self.top_files = []
        self.children = {}

# ─── TSV Parser (optimized) ─────────────────────────────────────────────

def parse_volume(filepath, vol_name, base_path=BASE_PATH):
    """Parse a single *_files.tsv into a directory tree and duplicate candidates."""
    now_ts = datetime.now().timestamp()
    day_seconds = 86400.0

    base = "{}/{}/".format(base_path, vol_name)
    baselen = len(base)
    root = Node()
    count = 0

    # Duplicate detection: (filename, size) -> list of (path, mtime)
    dupe_map = defaultdict(list)

    with open(filepath, buffering=8 * 1024 * 1024) as f:
        for line in f:
            parts = line.rstrip('\n').split('\t', 3)
            if len(parts) != 4:
                continue
            try:
                size = int(parts[0])
            except ValueError:
                continue

            path = parts[3]
            if not path.startswith(base):
                continue

            rel = path[baselen:]
            segs = rel.split('/')
            filename = segs[-1]
            dir_segs = segs[:-1]

            # Extension
            dot = filename.rfind('.')
            ext = filename[dot:].lower() if dot > 0 else "(none)"

            # Fast atime parsing
            atime_str = parts[1][:10]
            try:
                y, m, d = int(atime_str[:4]), int(atime_str[5:7]), int(atime_str[8:10])
                days = int((now_ts - datetime(y, m, d).timestamp()) / day_seconds)
            except (ValueError, IndexError):
                days = 9999
            abucket = atime_bucket(days)

            # Fast mtime parsing
            mtime_str = parts[2][:10]
            try:
                y, m, d = int(mtime_str[:4]), int(mtime_str[5:7]), int(mtime_str[8:10])
                mdays = int((now_ts - datetime(y, m, d).timestamp()) / day_seconds)
            except (ValueError, IndexError):
                mdays = 9999
            mbucket = atime_bucket(mdays)

            # Accumulate at root and each directory level
            node = root
            node.size += size
            node.files += 1
            node.atime[abucket] += size
            node.mtime[mbucket] += size
            e = node.exts
            if ext not in e:
                e[ext] = [0, 0]
            e[ext][0] += 1
            e[ext][1] += size

            for seg in dir_segs:
                ch = node.children
                if seg not in ch:
                    ch[seg] = Node()
                node = ch[seg]
                node.size += size
                node.files += 1
                node.atime[abucket] += size
                node.mtime[mbucket] += size
                e = node.exts
                if ext not in e:
                    e[ext] = [0, 0]
                e[ext][0] += 1
                e[ext][1] += size

            # Top files at deepest directory
            if size > 100 * 1024 * 1024:
                node.top_files.append((size, atime_str, filename))
                if len(node.top_files) > 15:
                    node.top_files.sort(key=lambda x: x[0], reverse=True)
                    node.top_files = node.top_files[:10]

            # Duplicate candidate (skip small files)
            if size >= DUPE_MIN_SIZE:
                dupe_map[(filename, size)].append((path, mtime_str))

            count += 1
            if count % 5000000 == 0:
                print(" {:,} files...".format(count), end='', flush=True)

    return root, count, dupe_map

# ─── Multiprocessing worker ─────────────────────────────────────────────

def _parse_worker(args):
    filepath, vol_name, base_path = args
    root, count, dupe_map = parse_volume(filepath, vol_name, base_path)
    tree = build_json(root, vol_name, depth=0)
    dupe_serial = {str(k): v for k, v in dupe_map.items() if len(v) > 1}
    return vol_name, tree, count, dupe_serial

# ─── Build JSON tree ────────────────────────────────────────────────────

def build_json(node, name, depth=0):
    jnode = {
        "name": name,
        "size": round_tib(node.size),
        "files": node.files,
        "at": [round_tib(a) for a in node.atime],
        "mt": [round_tib(m) for m in node.mtime],
    }

    top_exts = sorted(node.exts.items(), key=lambda x: x[1][1], reverse=True)[:15]
    if top_exts:
        jnode["exts"] = [[e, c, round_tib(s)] for e, (c, s) in top_exts]

    if node.top_files:
        node.top_files.sort(key=lambda x: x[0], reverse=True)
        jnode["tf"] = [[round(s / 1024 / 1024 / 1024, 1), a, n]
                       for s, a, n in node.top_files[:8]]

    if not node.children:
        return jnode

    prune = [
        (30, 0), (25, 0), (20, 0.01), (15, 0.05),
        (12, 0.1), (10, 0.5), (8, 1.0), (6, 5.0),
    ]
    idx = min(depth, len(prune) - 1)
    max_ch, min_tib = prune[idx]

    # UUID directory bucketing
    uuid_items, struct_items = [], []
    if len(node.children) >= 100 and depth <= 5:
        uuid_count = sum(1 for k in node.children if is_uuid(k))
        if uuid_count >= 100 and uuid_count > len(node.children) * 0.5:
            for k, child in node.children.items():
                (uuid_items if is_uuid(k) else struct_items).append((k, child))

    if uuid_items:
        children = []
        for k, child in sorted(struct_items, key=lambda x: x[1].size, reverse=True):
            if bytes_to_tib(child.size) >= min_tib and len(children) < max_ch:
                children.append(build_json(child, k, depth + 1))

        buckets_def = [("150+ GB", 150), ("100-150 GB", 100), ("60-100 GB", 60),
                       ("20-60 GB", 20), ("< 20 GB", 0)]
        bucket_nodes = {b: Node() for b, _ in buckets_def}
        bucket_counts = {b: 0 for b, _ in buckets_def}

        for k, child in uuid_items:
            gb = child.size / 1024 / 1024 / 1024
            bname = "< 20 GB"
            for bn, thresh in buckets_def:
                if gb >= thresh:
                    bname = bn
                    break
            bn = bucket_nodes[bname]
            bn.size += child.size
            bn.files += child.files
            for i in range(6):
                bn.atime[i] += child.atime[i]
                bn.mtime[i] += child.mtime[i]
            for ext, (c, s) in child.exts.items():
                if ext not in bn.exts:
                    bn.exts[ext] = [0, 0]
                bn.exts[ext][0] += c
                bn.exts[ext][1] += s
            bucket_counts[bname] += 1

        for bname, _ in buckets_def:
            bn = bucket_nodes[bname]
            if bn.size > 0:
                bj = build_json(bn, "UUID dirs {} ({})".format(bname, bucket_counts[bname]),
                               depth + 1)
                bj["flag"] = "unorganized"
                bj.pop("children", None)
                children.append(bj)

        children.sort(key=lambda x: x["size"], reverse=True)
        if children:
            jnode["children"] = children
    else:
        sorted_ch = sorted(node.children.items(), key=lambda x: x[1].size, reverse=True)
        children = []
        kept = 0
        other = Node()
        other_count = 0

        for k, child in sorted_ch:
            if kept < max_ch and bytes_to_tib(child.size) >= min_tib:
                children.append(build_json(child, k, depth + 1))
                kept += 1
            else:
                other.size += child.size
                other.files += child.files
                for i in range(6):
                    other.atime[i] += child.atime[i]
                    other.mtime[i] += child.mtime[i]
                for ext, (c, s) in child.exts.items():
                    if ext not in other.exts:
                        other.exts[ext] = [0, 0]
                    other.exts[ext][0] += c
                    other.exts[ext][1] += s
                other_count += 1

        if other.size > 0 and bytes_to_tib(other.size) >= 0.01:
            oj = build_json(other, "({} smaller items)".format(other_count), depth + 1)
            oj.pop("children", None)
            children.append(oj)

        if children:
            jnode["children"] = children

    return jnode

# ─── Duplicate analysis ─────────────────────────────────────────────────

def analyze_duplicates(all_dupe_maps):
    """Merge per-volume duplicate maps and compute summary stats."""
    merged = defaultdict(list)
    for dmap in all_dupe_maps:
        for key_str, paths in dmap.items():
            merged[key_str].extend(paths)

    dupes = {}
    for key_str, paths in merged.items():
        if len(paths) > 1:
            try:
                t = eval(key_str)
                dupes[t] = paths
            except:
                continue

    if not dupes:
        return [], 0, 0, 0, 0, {}

    total_sets = len(dupes)
    total_files = sum(len(v) for v in dupes.values())
    total_bytes = sum(k[1] * len(v) for k, v in dupes.items())
    reclaimable = sum(k[1] * (len(v) - 1) for k, v in dupes.items())

    sorted_dupes = sorted(dupes.items(),
                          key=lambda x: x[0][1] * (len(x[1]) - 1),
                          reverse=True)

    dupe_rows = []
    for (filename, size), paths in sorted_dupes[:DUPE_TOP_N]:
        copies = len(paths)
        locs = []
        for p, mt in paths:
            parent = p.rsplit('/', 1)[0].replace(BASE_PATH + "/", "")
            locs.append({"path": parent, "mtime": mt})
        dupe_rows.append({
            "name": filename,
            "size": size,
            "copies": copies,
            "reclaimable": size * (copies - 1),
            "locations": locs
        })

    return dupe_rows, total_sets, total_files, total_bytes, reclaimable, dupes

# ─── Per-directory duplicate stats ──────────────────────────────────────

def inject_dupe_stats(combined, dupes):
    """Add dc (dupe count) and ds (dupe size bytes) to each node in the tree."""
    if not dupes:
        return

    # Build per-directory dupe counts: dir_path -> (count, bytes)
    dir_dupes = defaultdict(lambda: [0, 0])
    for (filename, size), paths in dupes.items():
        if len(paths) < 2:
            continue
        for p, mt in paths:
            # Extract relative path segments
            rel = p.replace(BASE_PATH + "/", "")
            segs = rel.split('/')
            # Accumulate up the tree
            for depth in range(len(segs)):
                ancestor = '/'.join(segs[:depth + 1])
                dir_dupes[ancestor][0] += 1
                dir_dupes[ancestor][1] += size

    # Walk the JSON tree and inject stats
    def walk(node, prefix=""):
        name = node["name"]
        full = prefix + "/" + name if prefix else name
        if full in dir_dupes:
            node["dc"] = dir_dupes[full][0]
            node["ds"] = dir_dupes[full][1]
        # Also check just the name (for top-level volumes)
        if name in dir_dupes and "dc" not in node:
            node["dc"] = dir_dupes[name][0]
            node["ds"] = dir_dupes[name][1]
        if "children" in node:
            for child in node["children"]:
                walk(child, full)

    # Set root stats
    root_count = sum(v[0] for v in dir_dupes.values()
                     if '/' not in list(dir_dupes.keys())[0] or True)
    # Simpler: just sum across top-level volumes
    total_dc = 0
    total_ds = 0
    for child in combined.get("children", []):
        walk(child, "")
        total_dc += child.get("dc", 0)
        total_ds += child.get("ds", 0)
    combined["dc"] = total_dc
    combined["ds"] = total_ds

# ─── Unmodified % helper ────────────────────────────────────────────────

def unmod_pct(node):
    mt = node.get("mt", [0] * 6)
    total = sum(mt) or 1
    return (mt[2] + mt[3] + mt[4] + mt[5]) / total * 100

# ─── HTML dashboard generator ──────────────────────────────────────────

def generate_html(combined, scan_date, dupe_reclaimable, dupe_sets):
    data_js = json.dumps(combined)
    total_tib = combined["size"]
    total_files = combined["files"]
    at = combined["at"]
    mt = combined["mt"]
    stale_tib = sum(at[2:6])
    stale_pct = pct_of(stale_tib, total_tib)
    unmod_tib = sum(mt[2:6])
    unmod_pct_val = pct_of(unmod_tib, total_tib)

    return '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title} — File-Level Storage Audit</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=DM+Sans:wght@400;500;600;700&display=swap');
:root{{--bg:#0c0e12;--surface:#14171e;--border:#232836;--text:#d8dae0;--dim:#6b7085;--accent:#47b8e0;--warn:#e8a838;--danger:#e05252;--ok:#4caf68}}
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'DM Sans',sans-serif;background:var(--bg);color:var(--text);min-height:100vh}}
.hdr{{padding:16px 24px 12px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px}}
.hdr h1{{font-family:'JetBrains Mono',monospace;font-size:16px;font-weight:700;color:var(--accent);letter-spacing:-.3px}}
.hdr .sub{{font-size:12px;color:var(--dim);font-family:'JetBrains Mono',monospace;margin-top:2px}}
.btns{{display:flex;gap:8px}}
.btn{{font-family:'DM Sans',sans-serif;font-size:12px;font-weight:600;padding:6px 14px;border:1px solid var(--border);border-radius:5px;background:var(--surface);color:var(--text);cursor:pointer;transition:all .15s}}
.btn:hover{{border-color:var(--accent);color:var(--accent)}}
.btn-p{{background:var(--accent);color:var(--bg);border-color:var(--accent)}}
.btn-p:hover{{background:#5cc8ed}}
.stats{{display:flex;gap:20px;padding:10px 24px;border-bottom:1px solid var(--border);background:var(--surface);flex-wrap:wrap}}
.st{{display:flex;flex-direction:column;gap:1px}}
.st-l{{font-size:10px;text-transform:uppercase;letter-spacing:.7px;color:var(--dim);font-weight:600}}
.st-v{{font-family:'JetBrains Mono',monospace;font-size:14px;font-weight:700}}
.bc{{padding:8px 24px;font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--dim);border-bottom:1px solid var(--border);display:flex;align-items:center;gap:5px;min-height:34px;flex-wrap:wrap}}
.bc span{{cursor:pointer;transition:color .15s;white-space:nowrap}}.bc span:hover{{color:var(--accent)}}
.bc .sep{{color:var(--border);cursor:default}}.bc .sep:hover{{color:var(--border)}}
.bc .cur{{color:var(--text);font-weight:600}}
.main{{display:grid;grid-template-columns:1fr 320px;gap:0}}
@media(max-width:1100px){{.main{{grid-template-columns:1fr;}}.sidebar{{border-top:1px solid var(--border);max-height:none!important}}}}
.left{{border-right:1px solid var(--border)}}
.tmc{{padding:14px 24px 10px}}
#tm{{width:100%;height:48vh;min-height:300px;position:relative;border-radius:6px;overflow:hidden;border:1px solid var(--border);background:#0a0c10}}
.nd{{position:absolute;overflow:hidden;cursor:pointer;transition:opacity .1s;border:1px solid rgba(0,0,0,.35)}}
.nd:hover{{opacity:.85;z-index:10}}
.nd.flagged{{box-shadow:inset 0 0 0 2px var(--warn)}}
.lb{{position:absolute;top:3px;left:5px;right:5px;font-family:'JetBrains Mono',monospace;font-size:10px;font-weight:600;color:rgba(255,255,255,.92);pointer-events:none;text-shadow:0 1px 2px rgba(0,0,0,.8);line-height:1.25;overflow:hidden}}
.lb .sz{{font-weight:400;font-size:9px;opacity:.72;display:block}}
#tt{{position:fixed;background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:10px 14px;font-size:12px;pointer-events:none;z-index:1000;display:none;box-shadow:0 6px 24px rgba(0,0,0,.5);max-width:360px}}
#tt .tp{{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--accent);margin-bottom:4px;word-break:break-all}}
#tt .ts{{font-family:'JetBrains Mono',monospace;font-size:16px;font-weight:700;margin-bottom:2px}}
#tt .tpct{{font-size:11px;color:var(--dim)}}
#tt .tt-bar{{display:flex;height:12px;border-radius:2px;overflow:hidden;margin-top:6px}}
#tt .tt-seg{{min-width:1px}}
.sidebar{{padding:14px 16px;overflow-y:auto;max-height:calc(48vh + 300px)}}
.sb-section{{margin-bottom:16px}}
.sb-title{{font-size:10px;text-transform:uppercase;letter-spacing:.7px;color:var(--dim);font-weight:600;margin-bottom:8px}}
.sb-path{{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--accent);margin-bottom:4px;word-break:break-all}}
.sb-stats{{font-family:'JetBrains Mono',monospace;font-size:12px;margin-bottom:12px}}
.sb-stats span{{color:var(--dim)}}
.at-bar{{display:flex;height:22px;border-radius:3px;overflow:hidden;margin-bottom:8px}}
.at-seg{{display:flex;align-items:center;justify-content:center;font-family:'JetBrains Mono',monospace;font-size:9px;font-weight:600;color:rgba(255,255,255,.9);text-shadow:0 1px 1px rgba(0,0,0,.5);min-width:1px}}
.at-row{{display:flex;justify-content:space-between;font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--dim);margin-bottom:2px;padding:1px 0}}
.at-row .dot{{display:inline-block;width:8px;height:8px;border-radius:2px;margin-right:4px;vertical-align:middle}}
.ext-row{{display:flex;align-items:center;gap:6px;margin-bottom:4px;font-size:11px}}
.ext-name{{font-family:'JetBrains Mono',monospace;font-size:10px;min-width:50px;color:var(--text)}}
.ext-bar{{flex:1;height:14px;background:#1a1d26;border-radius:2px;overflow:hidden}}
.ext-fill{{height:100%;border-radius:2px}}
.ext-val{{font-family:'JetBrains Mono',monospace;font-size:9px;color:var(--dim);min-width:55px;text-align:right}}
.file-row{{display:flex;justify-content:space-between;gap:6px;padding:3px 0;border-bottom:1px solid var(--border);font-size:10px}}
.file-row:last-child{{border-bottom:none}}
.file-name{{font-family:'JetBrains Mono',monospace;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--text)}}
.file-size{{font-family:'JetBrains Mono',monospace;color:var(--dim);white-space:nowrap}}
.file-age{{font-family:'JetBrains Mono',monospace;white-space:nowrap;min-width:62px;text-align:right}}
.stit{{padding:10px 24px 4px;font-size:12px;font-weight:600;color:var(--dim);text-transform:uppercase;letter-spacing:.7px}}
.tc{{padding:0 24px 24px;overflow-x:auto}}
table{{width:100%;border-collapse:collapse;font-size:11px;background:var(--surface);border-radius:6px;overflow:hidden;border:1px solid var(--border)}}
th{{text-align:left;padding:6px 10px;font-size:10px;text-transform:uppercase;letter-spacing:.6px;color:var(--dim);font-weight:600;border-bottom:1px solid var(--border);cursor:pointer;user-select:none;white-space:nowrap}}
th:hover{{color:var(--accent)}}
th.sa::after{{content:' ▲';color:var(--accent)}}th.sd::after{{content:' ▼';color:var(--accent)}}
td{{padding:5px 10px;border-bottom:1px solid var(--border);font-family:'JetBrains Mono',monospace;font-size:10px}}
tr:last-child td{{border-bottom:none}}
tr:hover td{{background:rgba(71,184,224,.04)}}
.fg{{font-weight:600;color:var(--warn);font-size:10px}}
.age-stale{{color:var(--danger)}}.age-old{{color:var(--warn)}}.age-recent{{color:var(--ok)}}.age-active{{color:var(--accent)}}
</style>
</head>
<body>
<div class="hdr"><div><h1>{title} — File-Level Storage Audit</h1><div class="sub">{total_files_fmt} files scanned — atime + mtime storage analysis</div></div><div class="btns"><button class="btn" onclick="resetView()">Reset</button><button class="btn btn-p" onclick="exportCSV()">Export CSV</button></div></div>
<div class="stats">
<div class="st"><div class="st-l">Total</div><div class="st-v">{total_tib:,.1f} TiB ({pib:.2f} PiB)</div></div>
<div class="st"><div class="st-l">Files</div><div class="st-v">{total_files_fmt}</div></div>
<div class="st"><div class="st-l">Not Accessed 1y+</div><div class="st-v" style="color:var(--danger)">{stale_tib:,.1f} TiB ({stale_pct:.0f}%)</div></div>
<div class="st"><div class="st-l">Unmodified 1y+</div><div class="st-v" style="color:var(--warn)">{unmod_tib:,.1f} TiB ({unmod_pct:.0f}%)</div></div>
<div class="st"><div class="st-l">Duplicate Files</div><div class="st-v" style="color:var(--danger)">{dupe_reclaimable}</div></div>
<div class="st"><div class="st-l">Scan Date</div><div class="st-v" style="color:var(--dim)">{scan_date}</div></div>
</div>
<div class="bc" id="bc"><span class="cur">{display_label}</span></div>
<div class="main">
<div class="left">
<div class="tmc"><div id="tm"></div></div>
<div class="stit">Directory Breakdown</div>
<div class="tc"><table><thead><tr><th data-c="p">Path</th><th data-c="s" class="sd">Size (TiB)</th><th data-c="f">Files</th><th data-c="st">Not Accessed 1y+</th><th data-c="ex">Unmodified 1y+</th><th style="min-width:180px">Access Age</th><th></th></tr></thead><tbody id="tb"></tbody></table></div>
</div>
<div class="sidebar" id="sb">
<div class="sb-section"><div class="sb-title">Current Directory</div><div class="sb-path" id="sb-path">{display_label}</div><div class="sb-stats" id="sb-stats"></div></div>
<div class="sb-section"><div class="sb-title">Access Age Distribution</div><div id="sb-atime"></div></div>
<div class="sb-section"><div class="sb-title">File Types</div><div id="sb-exts"></div></div>
<div class="sb-section"><div class="sb-title">Largest Files</div><div id="sb-files"></div></div>
<div class="sb-section"><div class="sb-title">Duplicates</div><div id="sb-dupes"></div></div>
</div>
</div>
<div id="tt"></div>
<script>
const DATA={data_js};
const DL='{display_label}';
const VOL_HUE_POOL=[{{h:210,s0:72,s1:28,l0:55,l1:20}},{{h:28,s0:78,s1:32,l0:52,l1:22}},{{h:270,s0:65,s1:25,l0:52,l1:20}},{{h:150,s0:65,s1:25,l0:48,l1:20}},{{h:340,s0:70,s1:28,l0:50,l1:20}},{{h:55,s0:72,s1:28,l0:50,l1:22}},{{h:185,s0:68,s1:25,l0:48,l1:20}},{{h:310,s0:60,s1:25,l0:50,l1:20}},{{h:95,s0:60,s1:25,l0:46,l1:20}},{{h:5,s0:65,s1:28,l0:48,l1:20}}];
const VOL_HUES={{}};(DATA.children||[]).forEach((c,i)=>{{VOL_HUES[c.name]=VOL_HUE_POOL[i%VOL_HUE_POOL.length]}});
const AT_COLORS=['#47b8e0','#4caf68','#e8a838','#d4a63a','#e05252','#8b3a3a'];
const AT_LABELS=['< 90d','90d-1y','1-2y','2-3y','3-4y','4y+'];
let path=[],sortC='s',sortD='desc';
function getNode(p){{let n=DATA;for(const s of p){{if(n.children){{n=n.children.find(c=>c.name===s);if(!n)return DATA}}}}return n}}
function fmt(t){{if(t>=100)return t.toFixed(1)+' TiB';if(t>=1)return t.toFixed(2)+' TiB';if(t>=.001)return(t*1024).toFixed(1)+' GiB';return(t*1024*1024).toFixed(0)+' MiB'}}
function fmtB(b){{if(b>=1099511627776)return(b/1099511627776).toFixed(2)+' TiB';if(b>=1073741824)return(b/1073741824).toFixed(2)+' GiB';if(b>=1048576)return(b/1048576).toFixed(1)+' MiB';return Math.round(b/1024)+' KiB'}}
function fmtN(n){{return n.toLocaleString()}}
function stalePct(n){{const a=n.at||[0,0,0,0,0,0];const t=a.reduce((x,y)=>x+y,0)||1;return(a[2]+a[3]+a[4]+a[5])/t*100}}
function unmodPct(n){{const m=n.mt||[0,0,0,0,0,0];const t=m.reduce((x,y)=>x+y,0)||1;return(m[2]+m[3]+m[4]+m[5])/t*100}}
function ageClass(d){{if(!d)return'';try{{const dt=new Date(d),days=Math.floor((new Date()-dt)/86400000);if(days<90)return'age-active';if(days<365)return'age-recent';if(days<730)return'age-old';return'age-stale'}}catch(e){{return'age-stale'}}}}
function detectVol(){{return path.length>=1&&VOL_HUES[path[0]]?path[0]:null}}
function nodeColor(nd,idx){{const vol=detectVol();const u=unmodPct(nd)/100;if(vol&&VOL_HUES[vol]){{const v=VOL_HUES[vol],h=v.h+(idx%7-3)*3;return'hsl('+Math.round(h)+','+Math.round(v.s0-(v.s0-v.s1)*u)+'%,'+Math.round(v.l0-(v.l0-v.l1)*u)+'%)'}}if(VOL_HUES[nd.name]){{const v=VOL_HUES[nd.name];return'hsl('+v.h+','+Math.round(v.s0-(v.s0-v.s1)*u)+'%,'+Math.round(v.l0-(v.l0-v.l1)*u)+'%)'}}return'hsl(0,0%,'+Math.round(35-u*15)+'%)'}}
function squarify(ch,r){{if(!ch||!ch.length)return[];const s=[...ch].sort((a,b)=>b.size-a.size),res=[];let rem=[...s],cr={{...r}};while(rem.length>0){{const wide=cr.w>=cr.h,side=wide?cr.h:cr.w,ta=cr.w*cr.h,rs=rem.reduce((a,c)=>a+c.size,0);let row=[rem[0]],rws=rem[0].size;for(let i=1;i<rem.length;i++){{const ts=rws+rem[i].size,ra=(ts/rs)*ta,rside=ra/side;let wa=0;[...row,rem[i]].forEach(it=>{{const ia=(it.size/ts)*ra,is2=ia/rside;wa=Math.max(wa,Math.max(rside/is2,is2/rside))}});const cra=(rws/rs)*ta,crs=cra/side;let cw=0;row.forEach(it=>{{const ia=(it.size/rws)*cra,is2=ia/crs;cw=Math.max(cw,Math.max(crs/is2,is2/crs))}});if(wa<=cw){{row.push(rem[i]);rws+=rem[i].size}}else break}}const ra=(rws/rs)*ta,rside=ra/side;let off=0;row.forEach(it=>{{const f=it.size/rws,is2=side*f;let rect;if(wide)rect={{x:cr.x,y:cr.y+off,w:rside,h:is2}};else rect={{x:cr.x+off,y:cr.y,w:is2,h:rside}};res.push({{node:it,rect}});off+=is2}});if(wide)cr={{x:cr.x+rside,y:cr.y,w:cr.w-rside,h:cr.h}};else cr={{x:cr.x,y:cr.y+rside,w:cr.w,h:cr.h-rside}};rem=rem.slice(row.length)}}return res}}
function render(){{const c=document.getElementById('tm'),tt=document.getElementById('tt');c.innerHTML='';const node=getNode(path),items=node.children||[node],tot=items.reduce((a,i)=>a+i.size,0);const rect={{x:0,y:0,w:c.clientWidth,h:c.clientHeight}};squarify(items,rect).forEach((it,i)=>{{const el=document.createElement('div');el.className='nd'+(it.node.flag?' flagged':'');el.style.cssText='left:'+it.rect.x+'px;top:'+it.rect.y+'px;width:'+it.rect.w+'px;height:'+it.rect.h+'px;background:'+nodeColor(it.node,i);const pct=((it.node.size/tot)*100).toFixed(1),sp=stalePct(it.node).toFixed(0),up=unmodPct(it.node).toFixed(0);if(it.rect.w>45&&it.rect.h>24){{const lb=document.createElement('div');lb.className='lb';lb.innerHTML=it.node.name+(it.rect.w>65&&it.rect.h>38?'<span class="sz">'+fmt(it.node.size)+' · '+sp+'% not accessed · '+up+'% unmodified</span>':'');el.appendChild(lb)}}el.addEventListener('mouseenter',function(e){{const fp=[...path,it.node.name].join('/'),at=it.node.at||[0,0,0,0,0,0],total=at.reduce((a,b)=>a+b,0)||1;let bh='<div class="tt-bar">';at.forEach((v,j)=>{{const p2=v/total*100;if(p2>0.5)bh+='<div class="tt-seg" style="width:'+p2+'%;background:'+AT_COLORS[j]+'"></div>'}});bh+='</div>';tt.style.display='block';tt.innerHTML='<div class="tp">'+fp+'</div><div class="ts">'+fmt(it.node.size)+'</div><div class="tpct">'+fmtN(it.node.files||0)+' files · '+pct+'% of view · <span style="color:'+(sp>70?'var(--danger)':'var(--ok)')+'"><b>'+sp+'%</b> not accessed 1y+</span><br><span style="color:var(--warn)"><b>'+up+'%</b> unmodified 1y+</span>'+(it.node.flag?'<br><span style="color:var(--warn)">⚠ UUID directories</span>':'')+'</div>'+bh}});el.addEventListener('mousemove',function(e){{tt.style.left=Math.min(e.clientX+12,window.innerWidth-360)+'px';tt.style.top=Math.min(e.clientY+12,window.innerHeight-120)+'px'}});el.addEventListener('mouseleave',function(){{tt.style.display='none'}});el.addEventListener('click',function(){{if(it.node.children&&it.node.children.length>0){{path.push(it.node.name);render();updateBC();updateTable();updateSidebar()}}}});c.appendChild(el)}});updateTable();updateSidebar()}}
function updateBC(){{const bc=document.getElementById('bc');bc.innerHTML='';const r=document.createElement('span');r.textContent=DL;r.onclick=function(){{navigateTo([])}};bc.appendChild(r);path.forEach(function(p,i){{const sep=document.createElement('span');sep.className='sep';sep.textContent=' / ';bc.appendChild(sep);const s=document.createElement('span');s.textContent=p;s.className=i===path.length-1?'cur':'';s.onclick=function(){{navigateTo(path.slice(0,i+1))}};bc.appendChild(s)}})}}
function navigateTo(p){{path=p;render();updateBC()}}
function resetView(){{navigateTo([])}}
function updateTable(){{const node=getNode(path),items=node.children||[];const tb=document.getElementById('tb');tb.innerHTML='';let sorted=[...items];if(sortC==='s')sorted.sort(function(a,b){{return sortD==='desc'?b.size-a.size:a.size-b.size}});else if(sortC==='f')sorted.sort(function(a,b){{return sortD==='desc'?(b.files||0)-(a.files||0):(a.files||0)-(b.files||0)}});else if(sortC==='st')sorted.sort(function(a,b){{return sortD==='desc'?stalePct(b)-stalePct(a):stalePct(a)-stalePct(b)}});else if(sortC==='ex')sorted.sort(function(a,b){{return sortD==='desc'?unmodPct(b)-unmodPct(a):unmodPct(a)-unmodPct(b)}});else if(sortC==='p')sorted.sort(function(a,b){{return sortD==='desc'?b.name.localeCompare(a.name):a.name.localeCompare(b.name)}});sorted.forEach(function(it){{const tr=document.createElement('tr');const at=it.at||[0,0,0,0,0,0],atT=at.reduce(function(a,b){{return a+b}},0)||1;const sp=stalePct(it).toFixed(0),spC=sp>70?'age-stale':sp>40?'age-old':sp>10?'age-recent':'age-active';const up=unmodPct(it).toFixed(0),upC=up>70?'age-stale':up>40?'age-old':up>10?'age-recent':'age-active';let ah='<div style="display:flex;height:14px;border-radius:2px;overflow:hidden">';at.forEach(function(v,j){{const p2=v/atT*100;if(p2>0.5)ah+='<div style="width:'+p2+'%;background:'+AT_COLORS[j]+'" title="'+AT_LABELS[j]+': '+fmt(v)+'"></div>'}});ah+='</div>';const hd=it.children&&it.children.length>0;const fl=it.flag?'<span class="fg">⚠ '+it.flag+'</span>':(hd?'▸':'—');tr.innerHTML='<td style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+it.name+'">'+it.name+'</td><td>'+(it.size>=0.01?it.size.toFixed(2):fmt(it.size))+'</td><td>'+fmtN(it.files||0)+'</td><td class="'+spC+'">'+sp+'%</td><td class="'+upC+'">'+up+'%</td><td>'+ah+'</td><td>'+fl+'</td>';tr.style.cursor=hd?'pointer':'default';tr.addEventListener('click',function(){{if(hd){{path.push(it.name);render();updateBC();updateTable();updateSidebar()}}}});tb.appendChild(tr)}})}}
function updateSidebar(){{const node=getNode(path),sp=stalePct(node).toFixed(0),up=unmodPct(node).toFixed(0);document.getElementById('sb-path').textContent=path.length>0?path.join(' / '):DL;document.getElementById('sb-stats').innerHTML='<b>'+fmt(node.size)+'</b> <span>·</span> '+fmtN(node.files||0)+' files<br><span class="'+(sp>70?'age-stale':'age-active')+'">'+sp+'% not accessed 1y+</span><br><span style="color:var(--warn)">'+up+'% unmodified 1y+</span>';const sb=document.getElementById('sb-atime'),at=node.at||[0,0,0,0,0,0],atT=at.reduce(function(a,b){{return a+b}},0)||1;let ah='<div class="at-bar">';at.forEach(function(v,i){{const p2=v/atT*100;if(p2>0.3)ah+='<div class="at-seg" style="width:'+p2+'%;background:'+AT_COLORS[i]+'">'+(p2>6?Math.round(p2)+'%':'')+'</div>'}});ah+='</div>';at.forEach(function(v,i){{ah+='<div class="at-row"><span><span class="dot" style="background:'+AT_COLORS[i]+'"></span>'+AT_LABELS[i]+'</span><span>'+fmt(v)+'</span></div>'}});sb.innerHTML=ah;const se=document.getElementById('sb-exts');se.innerHTML='';const exts=node.exts||[],mx=exts.length>0?Math.max.apply(null,exts.map(function(e){{return e[2]}})):1;const ec=['#e06444','#3ba0d8','#d4a63a','#8b5cf6','#44b87a','#e8784c','#2d8ab8'];exts.forEach(function(e,i){{se.innerHTML+='<div class="ext-row"><div class="ext-name">'+e[0]+'</div><div class="ext-bar"><div class="ext-fill" style="width:'+(e[2]/mx*100).toFixed(1)+'%;background:'+ec[i%ec.length]+'"></div></div><div class="ext-val">'+fmt(e[2])+' ('+fmtN(e[1])+')</div></div>'}});if(!exts.length)se.innerHTML='<div style="color:var(--dim);font-size:11px">No file data</div>';const sf=document.getElementById('sb-files');sf.innerHTML='';const tf=node.tf||[];if(tf.length>0)tf.forEach(function(f){{const ac=ageClass(f[1]);sf.innerHTML+='<div class="file-row"><div class="file-name" title="'+f[2]+'">'+f[2]+'</div><div class="file-size">'+f[0].toFixed(1)+'G</div><div class="file-age '+ac+'">'+f[1]+'</div></div>'}});else sf.innerHTML='<div style="color:var(--dim);font-size:11px">No large files (>100MB)</div>';var sd=document.getElementById('sb-dupes');sd.innerHTML='<div style="font-family:JetBrains Mono,monospace;font-size:12px"><span style="color:var(--danger);font-weight:600">{dupe_reclaimable}</span><br><span style="color:var(--dim)">{dupe_sets:,} duplicate sets</span><br><a href="duplicates.html" style="color:var(--accent);font-size:11px">View full report →</a></div>'}}
document.querySelectorAll('[data-c]').forEach(function(th){{th.addEventListener('click',function(){{const c=th.dataset.c;if(sortC===c)sortD=sortD==='asc'?'desc':'asc';else{{sortC=c;sortD='desc'}};document.querySelectorAll('[data-c]').forEach(function(t){{t.classList.remove('sa','sd')}});th.classList.add(sortD==='asc'?'sa':'sd');updateTable()}})}});
function exportCSV(){{const rows=[['Path','Size_TiB','Files','Not_Accessed_1y+_TiB','Not_Accessed_1y+_Pct','Unmodified_1y+_TiB','Unmodified_1y+_Pct','Top_Extension']];function walk(nd,pp){{const p=pp?pp+'/'+nd.name:nd.name,at=nd.at||[0,0,0,0,0,0],st=at[2]+at[3]+at[4]+at[5],at2=at.reduce(function(a,b){{return a+b}},0)||1,mt=nd.mt||[0,0,0,0,0,0],um=mt[2]+mt[3]+mt[4]+mt[5],mt2=mt.reduce(function(a,b){{return a+b}},0)||1,te=(nd.exts&&nd.exts[0])?nd.exts[0][0]:'';rows.push([p,nd.size.toFixed(4),nd.files||0,st.toFixed(4),(st/at2*100).toFixed(1),um.toFixed(4),(um/mt2*100).toFixed(1),te]);if(nd.children)nd.children.forEach(function(c){{walk(c,p)}})}}walk(DATA,'');const csv=rows.map(function(r){{return r.map(function(c){{return typeof c==='string'&&c.indexOf(',')>=0?'"'+c+'"':c}}).join(',')}}).join('\\n');const blob=new Blob([csv],{{type:'text/csv'}}),a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='file_audit_{scan_date}.csv';a.click()}}
window.addEventListener('resize',function(){{render()}});render();updateBC()
</script>
</body>
</html>'''.format(
        title=TITLE,
        display_label=DISPLAY_LABEL,
        total_files_fmt='{:,}'.format(total_files),
        total_tib=total_tib,
        pib=total_tib / 1024,
        stale_tib=stale_tib,
        stale_pct=stale_pct,
        unmod_tib=unmod_tib,
        unmod_pct=unmod_pct_val,
        dupe_reclaimable=fmt_size(dupe_reclaimable),
        dupe_sets=dupe_sets,
        scan_date=scan_date,
        data_js=data_js,
    )

# ─── Standalone duplicate report generator ──────────────────────────────

def generate_dupe_report(dupe_rows, dupe_sets, dupe_files, dupe_bytes,
                         dupe_reclaimable, scanned_files, scan_date,
                         dashboard_filename="file_audit.html"):
    """Generate standalone interactive HTML duplicate report."""
    data_js = json.dumps(dupe_rows)

    return '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title} — Duplicate File Report</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=DM+Sans:wght@400;500;600;700&display=swap');
:root{{--bg:#0c0e12;--surface:#14171e;--border:#232836;--text:#d8dae0;--dim:#6b7085;--accent:#47b8e0;--warn:#e8a838;--danger:#e05252;--ok:#4caf68}}
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'DM Sans',sans-serif;background:var(--bg);color:var(--text);min-height:100vh}}
.hdr{{padding:16px 24px 12px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px}}
.hdr h1{{font-family:'JetBrains Mono',monospace;font-size:16px;font-weight:700;color:var(--accent);letter-spacing:-.3px}}
.hdr .sub{{font-size:12px;color:var(--dim);font-family:'JetBrains Mono',monospace;margin-top:2px}}
.stats{{display:flex;gap:20px;padding:10px 24px;border-bottom:1px solid var(--border);background:var(--surface);flex-wrap:wrap}}
.st{{display:flex;flex-direction:column;gap:1px}}
.st-l{{font-size:10px;text-transform:uppercase;letter-spacing:.7px;color:var(--dim);font-weight:600}}
.st-v{{font-family:'JetBrains Mono',monospace;font-size:14px;font-weight:700}}
.btn{{font-family:'DM Sans',sans-serif;font-size:12px;font-weight:600;padding:6px 14px;border:1px solid var(--border);border-radius:5px;background:var(--accent);color:var(--bg);border-color:var(--accent);cursor:pointer}}
.tc{{padding:16px 24px;overflow-x:auto}}
table{{width:100%;border-collapse:collapse;font-size:12px;background:var(--surface);border-radius:6px;overflow:hidden;border:1px solid var(--border)}}
th{{text-align:left;padding:8px 12px;font-size:10px;text-transform:uppercase;letter-spacing:.6px;color:var(--dim);font-weight:600;border-bottom:1px solid var(--border);cursor:pointer;user-select:none;white-space:nowrap}}
th:hover{{color:var(--accent)}}
th.sa::after{{content:' ▲';color:var(--accent)}}th.sd::after{{content:' ▼';color:var(--accent)}}
td{{padding:6px 12px;border-bottom:1px solid var(--border);font-family:'JetBrains Mono',monospace;font-size:11px}}
tr:last-child td{{border-bottom:none}}
tr:hover td{{background:rgba(71,184,224,.04)}}
.loc{{padding:4px 12px 4px 40px;font-size:10px;color:var(--dim);border-bottom:1px solid var(--border)}}
.loc:last-child{{border-bottom:none}}
.copies{{color:var(--warn);font-weight:600}}
.reclaimable{{color:var(--danger);font-weight:600}}
.toggle{{cursor:pointer;color:var(--accent);font-size:10px;margin-right:6px}}
</style>
</head>
<body>
<div class="hdr"><div><h1>{title} — Duplicate File Report</h1><div class="sub">Files with identical name + size across different directories</div></div><div style="display:flex;gap:8px"><a href="{dashboard_filename}" class="btn" style="text-decoration:none;background:var(--surface);color:var(--text)">← Dashboard</a><button class="btn" onclick="exportCSV()">Export CSV</button></div></div>
<div class="stats">
<div class="st"><div class="st-l">Duplicate Sets</div><div class="st-v">{dupe_sets:,}</div></div>
<div class="st"><div class="st-l">Duplicate Files</div><div class="st-v">{dupe_files:,}</div></div>
<div class="st"><div class="st-l">Total Size (all copies)</div><div class="st-v">{dupe_bytes}</div></div>
<div class="st"><div class="st-l">Reclaimable</div><div class="st-v reclaimable">{dupe_reclaimable}</div></div>
<div class="st"><div class="st-l">Files Scanned</div><div class="st-v">{scanned_files:,}</div></div>
<div class="st"><div class="st-l">Scan Date</div><div class="st-v" style="color:var(--dim)">{scan_date}</div></div>
</div>
<div class="tc">
<table>
<thead><tr><th data-c="n">File Name</th><th data-c="s" class="sd">Size</th><th data-c="c">Copies</th><th data-c="r">Reclaimable</th><th>Locations</th></tr></thead>
<tbody id="tb"></tbody>
</table>
</div>
<script>
const DATA={data_js};
let sortC='r',sortD='desc';
function fmt(b){{if(b>=1099511627776)return(b/1099511627776).toFixed(2)+' TiB';if(b>=1073741824)return(b/1073741824).toFixed(2)+' GiB';if(b>=1048576)return(b/1048576).toFixed(1)+' MiB';return Math.round(b/1024)+' KiB'}}
function fmtN(n){{return n.toLocaleString()}}
function render(){{const tb=document.getElementById('tb');tb.innerHTML='';let sorted=[...DATA];if(sortC==='s')sorted.sort(function(a,b){{return sortD==='desc'?b.size-a.size:a.size-b.size}});else if(sortC==='c')sorted.sort(function(a,b){{return sortD==='desc'?b.copies-a.copies:a.copies-b.copies}});else if(sortC==='r')sorted.sort(function(a,b){{return sortD==='desc'?b.reclaimable-a.reclaimable:a.reclaimable-b.reclaimable}});else if(sortC==='n')sorted.sort(function(a,b){{return sortD==='desc'?b.name.localeCompare(a.name):a.name.localeCompare(b.name)}});sorted.forEach(function(it,idx){{const tr=document.createElement('tr');tr.style.cursor='pointer';tr.innerHTML='<td><span class="toggle">▶</span>'+it.name+'</td><td>'+fmt(it.size)+'</td><td class="copies">'+it.copies+'</td><td class="reclaimable">'+fmt(it.reclaimable)+'</td><td style="color:var(--dim)">'+it.locations.length+' locations</td>';const lid='loc-'+idx;tr.addEventListener('click',function(){{const el=document.getElementById(lid),tog=tr.querySelector('.toggle');if(el){{el.remove();tog.textContent='▶'}}else{{const lr=document.createElement('tr');lr.id=lid;const td=document.createElement('td');td.colSpan=5;td.style.padding='0';let lh='';it.locations.forEach(function(l){{lh+='<div class="loc">'+l.path+' <span style="color:var(--dim);margin-left:8px">mtime: '+l.mtime+'</span></div>'}});td.innerHTML=lh;lr.appendChild(td);tr.parentNode.insertBefore(lr,tr.nextSibling);tog.textContent='▼'}}}});tb.appendChild(tr)}})}}
document.querySelectorAll('[data-c]').forEach(function(th){{th.addEventListener('click',function(){{const c=th.dataset.c;if(sortC===c)sortD=sortD==='asc'?'desc':'asc';else{{sortC=c;sortD='desc'}};document.querySelectorAll('th').forEach(function(t){{t.classList.remove('sa','sd')}});th.classList.add(sortD==='asc'?'sa':'sd');render()}})}});
function exportCSV(){{const rows=[['File_Name','Size_Bytes','Size_Human','Copies','Reclaimable_Bytes','Reclaimable_Human','Locations']];DATA.forEach(function(it){{const locs=it.locations.map(function(l){{return l.path}}).join('; ');rows.push(['"'+it.name+'"',it.size,fmt(it.size),it.copies,it.reclaimable,fmt(it.reclaimable),'"'+locs+'"'])}});const csv=rows.map(function(r){{return r.join(',')}}).join('\\n');const blob=new Blob([csv],{{type:'text/csv'}}),a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='duplicates_{scan_date}.csv';a.click()}}
render()
</script>
</body>
</html>'''.format(
        title=TITLE,
        dupe_sets=dupe_sets,
        dupe_files=dupe_files,
        dupe_bytes=fmt_size(dupe_bytes),
        dupe_reclaimable=fmt_size(dupe_reclaimable),
        scanned_files=scanned_files,
        scan_date=scan_date,
        data_js=data_js,
        dashboard_filename=dashboard_filename
    )

# ─── Main ───────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Build file-level audit dashboard")
    parser.add_argument("scan_dir", help="Directory containing *_files.tsv scan files")
    parser.add_argument("--output", "-o", default=None, help="Output HTML path")
    parser.add_argument("--parallel", "-p", type=int, default=0,
                        help="Parallel workers (0=auto, 1=sequential)")
    args = parser.parse_args()

    scan_dir = args.scan_dir.rstrip('/')

    scan_date = date.today().strftime("%Y-%m-%d")
    m = re.search(r'(\d{8})$', scan_dir)
    if m:
        d = m.group(1)
        scan_date = "{}-{}-{}".format(d[:4], d[4:6], d[6:8])

    # Discover TSV files
    vol_files = {}
    for f in sorted(glob.glob(os.path.join(scan_dir, "*_files.tsv"))):
        basename = os.path.basename(f)
        vol = basename.replace("_files.tsv", "")
        vol_files[vol] = f
        fsize = os.path.getsize(f)
        print("  {}: {} ({:.0f} MB)".format(vol, basename, fsize / 1024 / 1024))

    if not vol_files:
        print("ERROR: No *_files.tsv found in {}".format(scan_dir))
        sys.exit(1)

    total_bytes = sum(os.path.getsize(f) for f in vol_files.values())
    print("  Total scan data: {:.1f} GB".format(total_bytes / 1024 / 1024 / 1024))

    workers = args.parallel
    if workers == 0:
        workers = min(cpu_count(), len(vol_files), 8)
    use_parallel = workers > 1 and len(vol_files) > 1

    t0 = time.time()
    vol_trees = {}
    all_dupe_maps = []

    if use_parallel:
        print("\nProcessing {} volumes with {} workers...".format(len(vol_files), workers))
        work = [(vol_files[vol], vol, BASE_PATH) for vol in sorted(vol_files.keys())]
        with Pool(workers) as pool:
            for vol_name, tree, count, dupe_map in pool.imap_unordered(_parse_worker, work):
                up = unmod_pct(tree)
                print("  {} {:,} files, {:.1f} TiB, {:.0f}% unmodified 1y+".format(
                    vol_name, count, tree["size"], up))
                vol_trees[vol_name] = tree
                all_dupe_maps.append(dupe_map)
    else:
        print("\nProcessing {} volumes sequentially...".format(len(vol_files)))
        for vol in sorted(vol_files.keys()):
            print("Processing {}...".format(vol), end='', flush=True)
            root, count, dupe_map = parse_volume(vol_files[vol], vol)
            tree = build_json(root, vol, depth=0)
            vol_trees[vol] = tree
            all_dupe_maps.append({str(k): v for k, v in dupe_map.items() if len(v) > 1})
            up = unmod_pct(tree)
            print(" {:,} files, {:.1f} TiB, {:.0f}% unmodified 1y+".format(
                count, tree["size"], up))

    t1 = time.time()
    print("\nParsing complete in {:.0f}s".format(t1 - t0))

    # Duplicate analysis
    print("Analyzing duplicates...")
    dupe_rows, dupe_sets, dupe_files, dupe_bytes, dupe_reclaimable, dupes_dict = \
        analyze_duplicates(all_dupe_maps)
    print("  {:,} duplicate sets, {:,} files, {} reclaimable".format(
        dupe_sets, dupe_files, fmt_size(dupe_reclaimable)))

    # Combined root
    total_size = sum(t["size"] for t in vol_trees.values())
    total_files = sum(t["files"] for t in vol_trees.values())
    combined_at = [0.0] * 6
    combined_mt = [0.0] * 6
    for t in vol_trees.values():
        for i in range(6):
            combined_at[i] += t.get("at", [0] * 6)[i]
            combined_mt[i] += t.get("mt", [0] * 6)[i]

    combined = {
        "name": ROOT_LABEL,
        "size": round(total_size, 1),
        "files": total_files,
        "at": [round(a, 2) for a in combined_at],
        "mt": [round(m, 2) for m in combined_mt],
        "children": sorted(vol_trees.values(), key=lambda x: x["size"], reverse=True)
    }

    all_exts = {}
    for t in vol_trees.values():
        for e in (t.get("exts") or []):
            ext, cnt, sz = e
            if ext not in all_exts:
                all_exts[ext] = [0, 0]
            all_exts[ext][0] += cnt
            all_exts[ext][1] += sz
    top_exts = sorted(all_exts.items(), key=lambda x: x[1][1], reverse=True)[:15]
    combined["exts"] = [[e, c, round(s, 2)] for e, (c, s) in top_exts]

    # Generate HTML
    print("Generating HTML...")
    html = generate_html(combined, scan_date, dupe_reclaimable, dupe_sets)

    output_path = args.output or os.path.join(scan_dir, "file_audit.html")
    with open(output_path, 'w') as f:
        f.write(html)
    print("Dashboard: {} ({} KB)".format(output_path, len(html) // 1024))

    # Generate standalone duplicate report in same directory
    if dupe_rows:
        dashboard_basename = os.path.basename(output_path)
        dupe_report = generate_dupe_report(dupe_rows, dupe_sets, dupe_files,
                                           dupe_bytes, dupe_reclaimable,
                                           total_files, scan_date,
                                           dashboard_basename)
        dupe_path = os.path.join(os.path.dirname(output_path), "duplicates.html")
        with open(dupe_path, 'w') as f:
            f.write(dupe_report)
        print("Duplicates: {} ({} KB)".format(dupe_path, len(dupe_report) // 1024))

    t2 = time.time()
    print("Total time: {:.0f}s".format(t2 - t0))
    print("Done.")


if __name__ == "__main__":
    main()
