"""Turn the measurements into report.json, report.md and a self-contained
report.html. The HTML draws latency-over-time and throughput-over-time as
inline SVG (no external requests), works in light and dark, and gives every
chart axis labels, units and a one-line text summary so it is readable
without colour."""
from __future__ import annotations

import html
import json
from pathlib import Path


def _axis(x, lo, hi, a, b):
    return a if hi == lo else a + (x - lo) * (b - a) / (hi - lo)


def svg_line(series: dict, title: str, y_label: str, summary: str, width=720, height=260) -> str:
    """series: {name: [(t_seconds, value), ...]}. One polyline per name."""
    pad_l, pad_b, pad_t, pad_r = 56, 34, 28, 140
    xs = [p[0] for pts in series.values() for p in pts] or [0, 1]
    ys = [p[1] for pts in series.values() for p in pts] or [0, 1]
    xlo, xhi, ylo, yhi = min(xs), max(xs), 0, max(ys) * 1.1 or 1
    px = lambda t: _axis(t, xlo, xhi, pad_l, width - pad_r)
    py = lambda v: _axis(v, ylo, yhi, height - pad_b, pad_t)
    colors = ["var(--c1)", "var(--c2)", "var(--c3)", "var(--c4)", "var(--c5)"]
    out = [f'<svg viewBox="0 0 {width} {height}" role="img" aria-label="{html.escape(title)}. {html.escape(summary)}" class="chart">']
    out.append(f'<text x="{width/2}" y="16" class="t">{html.escape(title)}</text>')
    for frac in (0, 0.25, 0.5, 0.75, 1.0):
        v = yhi * frac
        y = py(v)
        out.append(f'<line x1="{pad_l}" y1="{y:.1f}" x2="{width-pad_r}" y2="{y:.1f}" class="grid"/>')
        out.append(f'<text x="{pad_l-6}" y="{y+3:.1f}" class="yl">{v:.0f}</text>')
    for frac in (0, 0.5, 1.0):
        t = xlo + (xhi - xlo) * frac
        out.append(f'<text x="{px(t):.1f}" y="{height-pad_b+16}" class="xl">{t:.0f}</text>')
    out.append(f'<text x="14" y="{height/2}" class="ax" transform="rotate(-90 14 {height/2})">{html.escape(y_label)}</text>')
    out.append(f'<text x="{(pad_l+width-pad_r)/2}" y="{height-4}" class="ax">time (s)</text>')
    for i, (name, pts) in enumerate(series.items()):
        if not pts:
            continue
        d = " ".join(f"{px(t):.1f},{py(v):.1f}" for t, v in pts)
        out.append(f'<polyline points="{d}" fill="none" stroke="{colors[i%5]}" stroke-width="1.8"/>')
        out.append(f'<rect x="{width-pad_r+8}" y="{pad_t+2+i*18}" width="10" height="10" fill="{colors[i%5]}"/>')
        out.append(f'<text x="{width-pad_r+22}" y="{pad_t+11+i*18}" class="lg">{html.escape(name)}</text>')
    out.append(f'<text x="{pad_l}" y="{height-2}" class="sm">{html.escape(summary)}</text>')
    out.append("</svg>")
    return "\n".join(out)


def svg_bars(rows: list, title: str, y_label: str, summary: str, width=720, height=260) -> str:
    """rows: [(label, {sub: value})]. Grouped bars (e.g. p50/p99 per operation)."""
    pad_l, pad_b, pad_t, pad_r = 56, 54, 28, 140
    subs = list(rows[0][1]) if rows else []
    vals = [v for _, d in rows for v in d.values()] or [1]
    yhi = max(vals) * 1.1 or 1
    py = lambda v: _axis(v, 0, yhi, height - pad_b, pad_t)
    colors = ["var(--c1)", "var(--c2)", "var(--c3)", "var(--c4)", "var(--c5)"]
    out = [f'<svg viewBox="0 0 {width} {height}" role="img" aria-label="{html.escape(title)}. {html.escape(summary)}" class="chart">']
    out.append(f'<text x="{width/2}" y="16" class="t">{html.escape(title)}</text>')
    for frac in (0, 0.25, 0.5, 0.75, 1.0):
        v = yhi * frac
        y = py(v)
        out.append(f'<line x1="{pad_l}" y1="{y:.1f}" x2="{width-pad_r}" y2="{y:.1f}" class="grid"/>')
        out.append(f'<text x="{pad_l-6}" y="{y+3:.1f}" class="yl">{v:.1f}</text>')
    out.append(f'<text x="14" y="{height/2}" class="ax" transform="rotate(-90 14 {height/2})">{html.escape(y_label)}</text>')
    n = max(1, len(rows))
    gw = (width - pad_l - pad_r) / n
    bw = gw / (len(subs) + 1)
    for i, (label, d) in enumerate(rows):
        x0 = pad_l + i * gw
        for j, sub in enumerate(subs):
            v = d[sub]
            x = x0 + j * bw + bw / 2
            out.append(f'<rect x="{x:.1f}" y="{py(v):.1f}" width="{bw*0.9:.1f}" height="{height-pad_b-py(v):.1f}" fill="{colors[j%5]}"/>')
        out.append(f'<text x="{x0+gw/2:.1f}" y="{height-pad_b+14}" class="xl" transform="rotate(20 {x0+gw/2:.1f} {height-pad_b+14})">{html.escape(label)}</text>')
    for j, sub in enumerate(subs):
        out.append(f'<rect x="{width-pad_r+8}" y="{pad_t+2+j*18}" width="10" height="10" fill="{colors[j%5]}"/>')
        out.append(f'<text x="{width-pad_r+22}" y="{pad_t+11+j*18}" class="lg">{html.escape(sub)}</text>')
    out.append(f'<text x="{pad_l}" y="{height-2}" class="sm">{html.escape(summary)}</text>')
    out.append("</svg>")
    return "\n".join(out)


CSS = """
:root{--bg:#ffffff;--fg:#1a1a1a;--muted:#666;--grid:#e3e3e3;--card:#f7f7f8;--border:#ddd;
--c1:#2563eb;--c2:#dc2626;--c3:#059669;--c4:#d97706;--c5:#7c3aed;}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#0f1115;--fg:#e8e8e8;--muted:#9aa0aa;--grid:#2a2d34;--card:#171a21;--border:#2a2d34;
--c1:#60a5fa;--c2:#f87171;--c3:#34d399;--c4:#fbbf24;--c5:#a78bfa;}}
:root[data-theme=dark]{--bg:#0f1115;--fg:#e8e8e8;--muted:#9aa0aa;--grid:#2a2d34;--card:#171a21;--border:#2a2d34;
--c1:#60a5fa;--c2:#f87171;--c3:#34d399;--c4:#fbbf24;--c5:#a78bfa;}
*{box-sizing:border-box}body{background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;padding:24px 16px;}
main{max-width:1000px;margin:0 auto}h1{font-size:1.5rem}h2{font-size:1.15rem;margin-top:2rem;border-bottom:1px solid var(--border);padding-bottom:4px}
table{border-collapse:collapse;width:100%;margin:12px 0;font-size:13px}th,td{border:1px solid var(--border);padding:5px 8px;text-align:right}
th:first-child,td:first-child{text-align:left}th{background:var(--card)}
.chart{width:100%;height:auto;background:var(--card);border:1px solid var(--border);border-radius:8px;margin:12px 0}
.chart .t{text-anchor:middle;font-size:13px;fill:var(--fg);font-weight:600}.chart .grid{stroke:var(--grid);stroke-width:1}
.chart .yl{text-anchor:end;font-size:10px;fill:var(--muted)}.chart .xl{text-anchor:middle;font-size:10px;fill:var(--muted)}
.chart .ax{text-anchor:middle;font-size:11px;fill:var(--muted)}.chart .lg{font-size:11px;fill:var(--fg)}.chart .sm{font-size:11px;fill:var(--muted)}
.muted{color:var(--muted)}.bad{color:var(--c2);font-weight:600}.good{color:var(--c3)}
"""


def _table(headers: list, rows: list) -> str:
    h = "".join(f"<th>{html.escape(str(x))}</th>" for x in headers)
    body = "".join("<tr>" + "".join(f"<td>{html.escape(str(c))}</td>" for c in r) + "</tr>" for r in rows)
    return f"<table><thead><tr>{h}</tr></thead><tbody>{body}</tbody></table>"


def write_html(report: dict, path: Path) -> None:
    parts = [f"<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>",
             f"<title>SmartDelegate load report</title><style>{CSS}</style></head><body><main>"]
    parts.append(f"<h1>SmartDelegate load report</h1><p class=muted>{html.escape(report['meta']['dated'])} · {html.escape(report['meta']['machine'])}</p>")
    parts.append(f"<p class=muted>{html.escape(report['meta']['note'])}</p>")
    for tname, t in report["targets"].items():
        parts.append(f"<h2>{html.escape(tname)}</h2>")
        st = t["steady"]
        parts.append(f"<p>steady state, {html.escape(t['mode'])}: <b>{st['throughput_rps']:.0f} req/s</b>, "
                     f"{st['errors_total']} errors, wrong-allow {st['wrong_allow']}.</p>")
        rows = [[op, s["count"], s["p50_ms"], s["p90_ms"], s["p99_ms"], s["p99_9_ms"], s["max_ms"]] for op, s in sorted(st["per_op"].items())]
        parts.append(_table(["operation", "calls", "p50 ms", "p90 ms", "p99 ms", "p99.9 ms", "max ms"], rows))
        if st.get("throughput_series"):
            parts.append(svg_line({"req/s": st["throughput_series"]}, f"{tname}: throughput over time", "req/s",
                                  f"mean {st['throughput_rps']:.0f} req/s over {len(st['throughput_series'])} s of steady state"))
        if st.get("latency_series"):
            parts.append(svg_line({"mean ms": st["latency_series"], "max ms": st["latency_max_series"]}, f"{tname}: latency over time", "ms",
                                  f"mean latency {st['per_op'].get('authorize_allow', {}).get('mean_ms', 0)} ms on the hot path; spikes are the max in each 1 s bucket"))
        barrows = [(op, {"p50": s["p50_ms"], "p99": s["p99_ms"]}) for op, s in sorted(st["per_op"].items())]
        parts.append(svg_bars(barrows, f"{tname}: p50 vs p99 by operation", "ms", "lower is better; the gap between p50 and p99 is the tail"))
        if t.get("resources", {}).get("series"):
            rs = t["resources"]["series"]
            parts.append(svg_line({"RSS MiB": [(x["t"], x["rss_kib"] / 1024) for x in rs]}, f"{tname}: resident memory over time", "MiB",
                                  f"RSS from {rs[0]['rss_kib']//1024} to {rs[-1]['rss_kib']//1024} MiB"))
            parts.append(svg_line({"CPU %": [(x["t"], x["cpu_pct"]) for x in rs if "cpu_pct" in x]}, f"{tname}: CPU over time", "% of one core",
                                  f"up to {max((x.get('cpu_pct', 0) for x in rs), default=0):.0f}% (2 cores available)"))
        if t.get("overload"):
            o = t["overload"]
            parts.append(f"<p><b>overload</b> (target {o['target_rps']:.0f} req/s): achieved {o['throughput_rps']:.0f} req/s, "
                         f"error rate {o['error_rate']*100:.1f}%, p99 {o['p99_ms']:.0f} ms, wrong-allow <b class={'bad' if o['wrong_allow'] else 'good'}>{o['wrong_allow']}</b>.</p>")
        if t.get("soak"):
            s = t["soak"]
            parts.append(f"<p><b>soak</b>: {s['decisions']} decisions. Audit {s['audit_bytes_per_decision']:.0f} bytes/decision; "
                         f"state.json {s['state_start_bytes']}→{s['state_end_bytes']} bytes.</p>")
            parts.append(svg_line({"authorize p50 ms": s["latency_vs_state"]}, f"{tname}: authorize latency as state grows", "ms",
                                  s["state_growth_verdict"]))
            parts.append(svg_line({"audit_verify ms": s["verify_vs_size"]}, f"{tname}: audit_verify time vs log size", "ms",
                                  f"{s['verify_verdict']}"))
    parts.append("</main></body></html>")
    path.write_text("\n".join(parts), encoding="utf-8")


def write_markdown(report: dict, path: Path) -> None:
    L = [f"# SmartDelegate load report", "", f"{report['meta']['dated']} — {report['meta']['machine']}", "", f"> {report['meta']['note']}", ""]
    for tname, t in report["targets"].items():
        st = t["steady"]
        L += [f"## {tname}", "", f"Steady state ({t['mode']}): **{st['throughput_rps']:.0f} req/s**, {st['errors_total']} errors, wrong-allow {st['wrong_allow']}.", "",
              "| operation | calls | p50 ms | p90 ms | p99 ms | p99.9 ms | max ms |", "|---|--:|--:|--:|--:|--:|--:|"]
        for op, s in sorted(st["per_op"].items()):
            L.append(f"| {op} | {s['count']} | {s['p50_ms']} | {s['p90_ms']} | {s['p99_ms']} | {s['p99_9_ms']} | {s['max_ms']} |")
        if st["errors_by_type"]:
            L += ["", "Errors: " + ", ".join(f"{k}={v}" for k, v in sorted(st["errors_by_type"].items()))]
        r = t.get("resources", {})
        if r.get("series"):
            L += ["", f"RSS {r['series'][0]['rss_kib']//1024}→{r['series'][-1]['rss_kib']//1024} MiB; peak CPU {r.get('peak_cpu_pct', 0):.0f}% of one core."]
        if t.get("overload"):
            o = t["overload"]
            L += ["", f"Overload (target {o['target_rps']:.0f} req/s): {o['throughput_rps']:.0f} req/s achieved, error rate {o['error_rate']*100:.1f}%, p99 {o['p99_ms']:.0f} ms, **wrong-allow {o['wrong_allow']}**."]
        if t.get("soak"):
            s = t["soak"]
            L += ["", f"Soak: {s['decisions']} decisions; audit {s['audit_bytes_per_decision']:.0f} bytes/decision; state.json {s['state_start_bytes']}→{s['state_end_bytes']} bytes.",
                  f"- {s['state_growth_verdict']}", f"- {s['verify_verdict']}"]
        if t.get("correctness"):
            c = t["correctness"]
            L += ["", f"Correctness: budget test allowed {c['allowed']} of {c['attempts']} spends (expected {c['expected_allowed']}); "
                  f"ledger {c['ledger']} of {c['expected_ledger']} budget; audit chain {'valid' if c['audit_valid'] else 'BROKEN'}; "
                  f"no lost decisions: {c['no_lost_decisions']}."]
        L.append("")
    path.write_text("\n".join(L), encoding="utf-8")
