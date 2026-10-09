import datetime
from pathlib import Path

TEMPLATE = """<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<title>تقرير فحص أمان - {domain}</title>
<style>
  body {{ font-family: 'Segoe UI', Tahoma, sans-serif; background: #0E1E1C; color: #EAF3EF; margin: 0; padding: 30px; }}
  .wrap {{ max-width: 720px; margin: 0 auto; }}
  h1 {{ font-size: 1.4rem; margin-bottom: 4px; }}
  .meta {{ color: #8FACA3; font-size: 0.9rem; margin-bottom: 24px; }}
  .grade-card {{ background: #15302B; border-radius: 12px; padding: 24px; text-align: center; margin-bottom: 24px; border: 1px solid #2A4A42; }}
  .grade-letter {{ font-size: 3.5rem; font-weight: 900; color: {grade_color}; }}
  .grade-label {{ color: {grade_color}; font-weight: 700; margin-top: 4px; }}
  .score-sub {{ color: #8FACA3; font-size: 0.85rem; margin-top: 6px; }}
  .section {{ background: #15302B; border: 1px solid #2A4A42; border-radius: 10px; padding: 16px 18px; margin-bottom: 14px; }}
  .section h3 {{ margin: 0 0 8px; font-size: 1rem; }}
  .badge {{ font-size: 0.72rem; padding: 2px 9px; border-radius: 20px; font-family: monospace; margin-left: 8px; }}
  .completed {{ background: #1E3B2E; color: #52B788; }}
  .failed {{ background: #3B1E1E; color: #E2634F; }}
  .summary {{ color: #8FACA3; font-size: 0.88rem; }}
  .reasons {{ list-style: none; padding: 0; margin: 8px 0 0; }}
  .reasons li {{ padding: 4px 0; font-size: 0.88rem; color: #E8B33D; }}
  footer {{ text-align: center; color: #8FACA3; font-size: 0.78rem; margin-top: 30px; }}
  @media print {{ body {{ background: white; color: black; }} .section, .grade-card {{ border: 1px solid #ccc; background: #f7f7f7; }} }}
</style>
</head>
<body>
<div class="wrap">
  <h1>تقرير فحص أمان الموقع</h1>
  <div class="meta">النطاق: {domain} &nbsp;|&nbsp; التاريخ: {date}</div>

  <div class="grade-card">
    <div class="grade-letter">{grade}</div>
    <div class="grade-label">{grade_label}</div>
    <div class="score-sub">النتيجة: {score}/100</div>
    {reasons_html}
  </div>

  {sections_html}

  <footer>تم إنشاؤه بواسطة ScanShield Desktop — فحص محلي، بدون أي بيانات مُرسلة لأي سيرفر</footer>
</div>
</body>
</html>"""


def _render_reasons(reasons: list[str]) -> str:
    if not reasons:
        return ""
    items = "".join(f"<li>• {r}</li>" for r in reasons)
    return f'<ul class="reasons">{items}</ul>'


def _render_sections(results: dict) -> str:
    html = ""
    for key, result in results.items():
        status = result.get("status", "unknown")
        badge_class = "completed" if status == "completed" else "failed"
        summary = result.get("summary") or result.get("error") or ""
        html += f"""
  <div class="section">
    <h3>{result.get('tool', key)} <span class="badge {badge_class}">{status}</span></h3>
    <div class="summary">{summary}</div>
  </div>"""
    return html


def export_report(domain: str, results: dict, grade_info: dict, out_path: Path) -> Path:
    html = TEMPLATE.format(
        domain=domain,
        date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
        grade=grade_info["grade"],
        grade_color=grade_info["color"],
        grade_label=grade_info["label"],
        score=grade_info["score"],
        reasons_html=_render_reasons(grade_info["top_reasons"]),
        sections_html=_render_sections(results),
    )
    out_path.write_text(html, encoding="utf-8")
    return out_path
