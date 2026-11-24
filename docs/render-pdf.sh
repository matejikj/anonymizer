#!/usr/bin/env bash
# Renders PCAP_ANONYMIZATION_OVERVIEW.md (or any .md passed as $1) to a PDF, A4,
# using `marked` (Markdown -> HTML) and headless Chrome (HTML -> PDF).
#
# Usage:
#   ./render-pdf.sh [input.md] [output.pdf]
# Defaults to PCAP_ANONYMIZATION_OVERVIEW.md -> PCAP_ANONYMIZATION_OVERVIEW.pdf
# in this script's own directory.
#
# Requires: npx (Node.js) and a Chrome/Chromium binary (google-chrome,
# google-chrome-stable, or chromium) on PATH.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INPUT_MD="${1:-$SCRIPT_DIR/PCAP_ANONYMIZATION_OVERVIEW.md}"
OUTPUT_PDF="${2:-${INPUT_MD%.md}.pdf}"

if [[ ! -f "$INPUT_MD" ]]; then
  echo "Input file not found: $INPUT_MD" >&2
  exit 1
fi

CHROME_BIN=""
for candidate in google-chrome google-chrome-stable chromium chromium-browser; do
  if command -v "$candidate" >/dev/null 2>&1; then
    CHROME_BIN="$candidate"
    break
  fi
done
# macOS app bundle (common on developer machines; not usually on PATH).
if [[ -z "$CHROME_BIN" && -x "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" ]]; then
  CHROME_BIN="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
fi
if [[ -z "$CHROME_BIN" && -x "/Applications/Chromium.app/Contents/MacOS/Chromium" ]]; then
  CHROME_BIN="/Applications/Chromium.app/Contents/MacOS/Chromium"
fi
if [[ -z "$CHROME_BIN" ]]; then
  echo "No Chrome/Chromium binary found (PATH or /Applications)." >&2
  exit 1
fi

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

BODY_HTML="$WORK_DIR/body.html"
FULL_HTML="$WORK_DIR/full.html"

echo "Converting Markdown -> HTML ($INPUT_MD)..."
npx --yes marked "$INPUT_MD" -o "$BODY_HTML"

cat > "$FULL_HTML" <<'HTML_HEAD'
<!DOCTYPE html>
<html lang="cs">
<head>
<meta charset="utf-8">
<title>rnd-log-anonymizer — přehled</title>
<style>
  @page { size: A4; margin: 13mm 16mm; }
  * { box-sizing: border-box; }
  body {
    font-family: "Segoe UI", "Helvetica Neue", Arial, sans-serif;
    font-size: 9.6pt;
    line-height: 1.32;
    color: #1a1a1a;
    margin: 0;
  }
  h2, h3 { break-after: avoid-page; page-break-after: avoid; }
  table, tr { break-inside: avoid; page-break-inside: avoid; }
  p, li { orphans: 3; widows: 3; }
  .cover { text-align: center; margin-bottom: 5mm; }
  .cover h1 {
    font-size: 21pt;
    margin: 0 0 2mm 0;
    color: #0f3d5c;
    letter-spacing: 0.3px;
  }
  .cover h2 {
    font-size: 12pt;
    font-weight: 500;
    margin: 0;
    color: #3a3a3a;
    border: none;
  }
  h1 { font-size: 15pt; color: #0f3d5c; }
  h2 {
    font-size: 12.5pt;
    color: #0f3d5c;
    border-bottom: 1.5pt solid #0f3d5c;
    padding-bottom: 0.8mm;
    margin-top: 0;
    margin-bottom: 2.4mm;
  }
  h3 {
    font-size: 10.3pt;
    color: #0f3d5c;
    margin-bottom: 1.1mm;
  }
  p { margin: 0 0 1.7mm 0; text-align: justify; }
  ul, ol { margin: 0 0 1.7mm 0; padding-left: 4.2mm; }
  li { margin-bottom: 0.6mm; }
  strong { color: #0a2a40; }
  table {
    border-collapse: collapse;
    width: 100%;
    margin: 0 0 2.8mm 0;
    font-size: 8.6pt;
  }
  th, td {
    border: 0.6pt solid #b9c6ce;
    padding: 1.1mm 1.6mm;
    vertical-align: top;
    text-align: left;
  }
  th {
    background: #e8f0f4;
    color: #0f3d5c;
    font-weight: 600;
  }
  tr:nth-child(even) td { background: #f7fafb; }
  code {
    background: #eef2f4;
    padding: 0.3mm 1mm;
    border-radius: 2px;
    font-size: 8.1pt;
    font-family: "Consolas", "Courier New", monospace;
  }
</style>
</head>
<body>
HTML_HEAD

cat "$BODY_HTML" >> "$FULL_HTML"
echo "</body></html>" >> "$FULL_HTML"

echo "Rendering HTML -> PDF ($OUTPUT_PDF)..."
"$CHROME_BIN" \
  --headless --disable-gpu --no-sandbox \
  --print-to-pdf="$OUTPUT_PDF" \
  --print-to-pdf-no-header \
  --no-pdf-header-footer \
  "file://$FULL_HTML" >/dev/null 2>&1

echo "Done: $OUTPUT_PDF"
