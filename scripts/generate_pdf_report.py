#!/usr/bin/env python3
"""
generate_pdf_report.py — Converts HardSec2026_Report.md into a professional PDF
with embedded high-resolution plots, styled tables, and academic typography.
"""

import os
import subprocess
import markdown

REPORT_MD = "/home/abhi/Desktop/Hardsec/report/HardSec2026_Report.md"
REPORT_HTML = "/home/abhi/Desktop/Hardsec/report/HardSec2026_Report.html"
REPORT_PDF = "/home/abhi/Desktop/Hardsec/report/HardSec2026_Report.pdf"
PLOT_DIR = "/home/abhi/Desktop/Hardsec/results/plots"

def build_pdf():
    with open(REPORT_MD, "r") as f:
        md_text = f.read()

    # Convert Markdown to HTML
    html_content = markdown.markdown(md_text, extensions=['tables', 'fenced_code'])

    # Embed CSS styling for publication-grade layout
    styled_html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>HardSec 2026 Technical Report</title>
<style>
  @page {{
    size: A4;
    margin: 20mm 15mm 20mm 15mm;
    @bottom-center {{
      content: counter(page);
    }}
  }}
  body {{
    font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
    color: #222;
    line-height: 1.5;
    font-size: 10.5pt;
    margin: 0;
    padding: 0;
  }}
  h1 {{
    font-size: 19pt;
    color: #0d233a;
    border-bottom: 2px solid #2f7ed8;
    padding-bottom: 6px;
    margin-top: 0;
    line-height: 1.25;
  }}
  h2 {{
    font-size: 14pt;
    color: #1c3d5a;
    border-bottom: 1px solid #ddd;
    padding-bottom: 4px;
    margin-top: 18px;
    margin-bottom: 8px;
  }}
  h3 {{
    font-size: 11.5pt;
    color: #2b5b84;
    margin-top: 12px;
    margin-bottom: 6px;
  }}
  p {{
    margin: 6px 0;
    text-align: justify;
  }}
  table {{
    border-collapse: collapse;
    width: 100%;
    margin: 14px 0;
    font-size: 9.5pt;
  }}
  th, td {{
    border: 1px solid #ccc;
    padding: 6px 8px;
    text-align: left;
  }}
  th {{
    background-color: #f0f4f8;
    font-weight: bold;
    color: #1c3d5a;
  }}
  tr:nth-child(even) {{
    background-color: #fafbfc;
  }}
  blockquote {{
    border-left: 4px solid #2f7ed8;
    background-color: #f4f8fc;
    margin: 10px 0;
    padding: 8px 12px;
    font-style: italic;
  }}
  code {{
    font-family: 'Menlo', 'Monaco', 'Courier New', monospace;
    font-size: 9pt;
    background-color: #f3f4f6;
    padding: 2px 4px;
    border-radius: 3px;
  }}
  pre {{
    background-color: #f8f9fa;
    border: 1px solid #e1e4e8;
    border-radius: 4px;
    padding: 10px;
    overflow-x: auto;
    font-size: 8.5pt;
  }}
  .figure-box {{
    text-align: center;
    margin: 16px 0;
    page-break-inside: avoid;
  }}
  .figure-box img {{
    max-width: 90%;
    height: auto;
    border: 1px solid #ddd;
    border-radius: 4px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.08);
  }}
  .figure-caption {{
    font-size: 9pt;
    font-weight: bold;
    color: #444;
    margin-top: 6px;
  }}
  .page-break {{
    page-break-after: always;
  }}
</style>
</head>
<body>

{html_content}

<div class="page-break"></div>

<h2>Visual Results & Side-Channel Verification Gallery</h2>

<div class="figure-box">
  <img src="file://{PLOT_DIR}/tvla_comparison_unpatched_vs_patched.png" alt="TVLA Side-by-Side Comparison">
  <div class="figure-caption">Figure 1: Test Vector Leakage Assessment (TVLA) — Unpatched Stage 1 Design (|t|_max = 102.5, leaking) vs. Stage 2 Masked Design (|t|_max = 2.25, fully compliant &lt; 4.5).</div>
</div>

<div class="figure-box">
  <img src="file://{PLOT_DIR}/cpa_convergence_pge.png" alt="CPA Key Convergence Unpatched">
  <div class="figure-caption">Figure 2: CPA Key Byte Convergence (Unpatched Design) — Partial Guessing Entropy (PGE) drops to 0 across all 16 bytes simultaneously by 420 traces.</div>
</div>

<div class="figure-box">
  <img src="file://{PLOT_DIR}/cpa_correlation_vs_time_all.png" alt="CPA 16 Key Bytes Correlation vs Time">
  <div class="figure-caption">Figure 3: CPA Pearson Correlation vs. Clock Cycle for All 16 Key Bytes (Unpatched Design) — Sharp correlation spikes (|r| ~ 0.20–0.27) at Cycle 10.</div>
</div>

<div class="page-break"></div>

<div class="figure-box">
  <img src="file://{PLOT_DIR}/cpa_correlation_vs_time_patched_byte0.png" alt="CPA on Masked Design">
  <div class="figure-caption">Figure 4: CPA Correlation vs. Time on Masked AES-128 (Byte 0) — Correct key correlation completely collapsed into the noise floor (|r| &lt; 0.05).</div>
</div>

<div class="figure-box">
  <img src="file://{PLOT_DIR}/cpa_convergence_pge_patched.png" alt="CPA Convergence on Masked Design">
  <div class="figure-caption">Figure 5: CPA Convergence on Masked AES-128 — Key recovery fails completely; Partial Guessing Entropy (PGE) remains high (~128) across all 5,000 traces.</div>
</div>

</body>
</html>
"""

    with open(REPORT_HTML, "w") as f:
        f.write(styled_html)
    print(f"  ✓ Saved HTML: {REPORT_HTML}")

    # Convert HTML to PDF via headless Google Chrome
    cmd = [
        "google-chrome",
        "--headless",
        "--disable-gpu",
        "--no-sandbox",
        "--allow-file-access-from-files",
        f"--print-to-pdf={REPORT_PDF}",
        REPORT_HTML
    ]
    print("Converting HTML to PDF with Google Chrome...")
    subprocess.run(cmd, check=True)
    print(f"  ✓ Generated PDF: {REPORT_PDF}")

if __name__ == "__main__":
    build_pdf()
