#!/bin/bash
#
# file_scan.sh — File-level storage audit scan + dashboard rebuild
#
# Scans all files under BASEPATH using find,
# captures size/atime/mtime, then builds an interactive treemap dashboard.
#
# Large directories (with many subdirectories) are automatically split
# into parallel sub-finds for faster scanning.
#
# Usage:
#   ./file_scan.sh [output_html]
#
# Examples:
#   ./file_scan.sh
#   ./file_scan.sh /path/to/output/file_audit.html
#
# Cron (weekly, Sunday 3am):
#   0 3 * * 0 /path/to/scripts/file_scan.sh /path/to/output/file_audit.html >> /tmp/file_scan.log 2>&1
#

OUTPUT_HTML="${1:-}"
DATE=$(date +%Y%m%d)
BASEPATH="/mnt/storage"
OUTDIR="/path/to/scans/file_scan_${DATE}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILDER="${SCRIPT_DIR}/file_audit_builder.py"

# Threshold: directories with more than this many subdirs get split into parallel sub-finds
SPLIT_THRESHOLD=50

# Auto-discover all subdirectories under Workspace (handles spaces)
VOLUMES=()
for d in "$BASEPATH"/*/; do
    [ -d "$d" ] && VOLUMES+=("$(basename "${d%/}")")
done

mkdir -p "$OUTDIR"

echo "=================================================="
echo "File audit scan — $(date)"
echo "Directories: ${#VOLUMES[@]}"
echo "Output: $OUTDIR"
echo "=================================================="

# Verify mounts
for vol in "${VOLUMES[@]}"; do
    if [ ! -d "${BASEPATH}/${vol}" ]; then
        echo "ERROR: ${BASEPATH}/${vol} not accessible. Aborting."
        exit 1
    fi
done

# Maximum parallel find processes for split directories
MAX_PARALLEL=8

# Phase 1: file scans (parallel — with auto-split for large directories)
for vol in "${VOLUMES[@]}"; do
    volpath="${BASEPATH}/${vol}"

    # Count immediate subdirectories
    subdir_count=$(find "$volpath" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | wc -l)

    if [ "$subdir_count" -gt "$SPLIT_THRESHOLD" ]; then
        # Large directory — split into throttled parallel sub-finds
        echo "[$(date +%H:%M:%S)] Starting SPLIT scan on $vol ($subdir_count subdirs, ${MAX_PARALLEL} parallel)..."
        splitdir="${OUTDIR}/_split_${vol}"
        mkdir -p "$splitdir"

        # Scan root-level files (non-recursive)
        find "$volpath" -maxdepth 1 -type f -printf '%s\t%A+\t%T+\t%p\n' > "${splitdir}/_rootfiles.tsv" 2>/dev/null

        # Scan subdirectories with throttled parallelism
        find "$volpath" -maxdepth 1 -mindepth 1 -type d -print0 2>/dev/null | \
            xargs -0 -I{} -P "${MAX_PARALLEL}" sh -c \
            'subname=$(basename "{}"); find "{}" -type f -printf "%s\t%A+\t%T+\t%p\n" > "'"${splitdir}"'/${subname}_files.tsv" 2>/dev/null'
        echo "[$(date +%H:%M:%S)] Split scan complete for $vol."
    else
        # Normal directory — single find
        echo "[$(date +%H:%M:%S)] Starting file scan on $vol..."
        find "$volpath/" -type f -printf '%s\t%A+\t%T+\t%p\n' > "${OUTDIR}/${vol}_files.tsv" 2>/dev/null &
    fi
done

echo "Waiting for remaining file scans..."
wait
echo "[$(date +%H:%M:%S)] All file scans complete."

# Phase 1b: merge split scans back into single TSV per volume
for vol in "${VOLUMES[@]}"; do
    splitdir="${OUTDIR}/_split_${vol}"
    if [ -d "$splitdir" ]; then
        echo "[$(date +%H:%M:%S)] Merging split scan for $vol..."
        cat "${splitdir}"/*.tsv > "${OUTDIR}/${vol}_files.tsv" 2>/dev/null
        rm -rf "$splitdir"
        echo "[$(date +%H:%M:%S)] Merged $vol."
    fi
done

# Phase 2: summary
total_files=0
for vol in "${VOLUMES[@]}"; do
    tsv="${OUTDIR}/${vol}_files.tsv"
    if [ -f "$tsv" ]; then
        count=$(wc -l < "$tsv")
        total_files=$((total_files + count))
        echo "  $vol: ${count} files"
    fi
done
echo "  TOTAL: ${total_files} files"

# Phase 3: generate dashboard
if [ -f "$BUILDER" ]; then
    echo "[$(date +%H:%M:%S)] Building dashboard..."
    BUILD_ARGS="$OUTDIR"
    if [ -n "$OUTPUT_HTML" ]; then
        BUILD_ARGS="$BUILD_ARGS --output $OUTPUT_HTML"
    fi
    python3 "$BUILDER" $BUILD_ARGS
    echo "[$(date +%H:%M:%S)] Dashboard published."
else
    echo "WARNING: Builder not found at $BUILDER — skipping dashboard generation."
    echo "Run manually: python3 /path/to/file_audit_builder.py $OUTDIR"
fi

# Phase 4: generate standalone duplicate report
DUPE_FINDER="${SCRIPT_DIR}/duplicate_finder.py"
if [ -f "$DUPE_FINDER" ]; then
    DUPE_OUTPUT="$(dirname "${OUTPUT_HTML:-$OUTDIR/file_audit.html}")/duplicates.html"
    echo "[$(date +%H:%M:%S)] Building duplicate report..."
    python3 "$DUPE_FINDER" "$OUTDIR" --output "$DUPE_OUTPUT"
    echo "[$(date +%H:%M:%S)] Duplicate report published."
fi

echo ""
echo "=================================================="
echo "Complete: $(date)"
echo "Scan dir: $OUTDIR"
if [ -n "$OUTPUT_HTML" ]; then
    echo "Dashboard: $OUTPUT_HTML"
fi
echo "=================================================="
