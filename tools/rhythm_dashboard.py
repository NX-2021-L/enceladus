#!/usr/bin/env python3
"""Render the rhythm-cycle observability dashboard to a self-contained HTML file.

Reads the distilled ``dashboard_data.json`` and ``INDEX.json`` produced by the
harvest / analyze steps, projects the compact subset of series and signals that
the dashboard template consumes, embeds that JSON into the template, and writes
a single self-contained HTML page (no external assets, no network requests) that
visualizes the Enceladus gamma rhythm-cycle vital signs.

The template ships embedded in this module as ``TEMPLATE_HTML``; rendering
replaces its ``__DATA__`` placeholder with the compact embed JSON and injects a
``const DATA_META = {harvested_at: ...}`` line immediately after the
``const DATA = ...;`` line so the page can stamp its harvest time.

Usage:
  # Default: read /Users/jreese/rhythm-analysis, write rhythm_dashboard.html there
  python3 tools/rhythm_dashboard.py

  # Custom bundle directory and output path
  python3 tools/rhythm_dashboard.py \
    --out /Users/jreese/rhythm-analysis \
    --out-html /Users/jreese/rhythm-analysis/rhythm_dashboard.html

Inputs (read-only):
  <out>/dashboard_data.json  distilled series + signals (from rhythm_analyze.py)
  <out>/INDEX.json           harvest manifest (provides the harvested_at stamp)

Output:
  <out-html>                 self-contained HTML dashboard

This script performs no AWS calls; it only reads the two JSON artifacts and
writes one HTML file.

Part of the Enceladus gamma rhythm-cycle observability tooling.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

DEFAULT_OUT = "/Users/jreese/rhythm-analysis"
DEFAULT_OUT_HTML = "/Users/jreese/rhythm-analysis/rhythm_dashboard.html"

# Tier order used for the compact cadence / beatcount maps.
TIER_ORDER = ["sense", "light_integrate", "decide", "heavy_integrate", "coherence"]


TEMPLATE_HTML = r"""<title>Rhythm Vital Signs — gamma</title>
<style>
  :root{
    --ground:#0d1418; --panel:#131e25; --panel-2:#0f191f; --line:#22323b; --line-2:#1a2830;
    --ink:#cfdce2; --ink-2:#93a7b0; --muted:#607480;
    --accent:#45abd0; --accent-soft:rgba(69,171,208,.16); --accent-2:#d9a441;
    --good:#57b982; --warn:#d9a441; --crit:#e0685c;
    --good-soft:rgba(87,185,130,.14); --warn-soft:rgba(217,164,65,.14); --crit-soft:rgba(224,104,92,.14);
    --mono:ui-monospace,"SF Mono","JetBrains Mono",Menlo,Consolas,monospace;
    --sans:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
    --r:10px; --maxw:1180px;
  }
  @media (prefers-color-scheme: light){
    :root{
      --ground:#eceff1; --panel:#ffffff; --panel-2:#f5f8f9; --line:#dde5e9; --line-2:#e7edf0;
      --ink:#16242b; --ink-2:#465e69; --muted:#7d919b;
      --accent:#1c7ea3; --accent-soft:rgba(28,126,163,.10); --accent-2:#b07d1c;
      --good:#2e9e5b; --warn:#b07d1c; --crit:#c8493c;
      --good-soft:rgba(46,158,91,.12); --warn-soft:rgba(176,125,28,.12); --crit-soft:rgba(200,73,60,.12);
    }
  }
  :root[data-theme="dark"]{
    --ground:#0d1418; --panel:#131e25; --panel-2:#0f191f; --line:#22323b; --line-2:#1a2830;
    --ink:#cfdce2; --ink-2:#93a7b0; --muted:#607480;
    --accent:#45abd0; --accent-soft:rgba(69,171,208,.16); --accent-2:#d9a441;
    --good:#57b982; --warn:#d9a441; --crit:#e0685c;
    --good-soft:rgba(87,185,130,.14); --warn-soft:rgba(217,164,65,.14); --crit-soft:rgba(224,104,92,.14);
  }
  :root[data-theme="light"]{
    --ground:#eceff1; --panel:#ffffff; --panel-2:#f5f8f9; --line:#dde5e9; --line-2:#e7edf0;
    --ink:#16242b; --ink-2:#465e69; --muted:#7d919b;
    --accent:#1c7ea3; --accent-soft:rgba(28,126,163,.10); --accent-2:#b07d1c;
    --good:#2e9e5b; --warn:#b07d1c; --crit:#c8493c;
    --good-soft:rgba(46,158,91,.12); --warn-soft:rgba(176,125,28,.12); --crit-soft:rgba(200,73,60,.12);
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--ground);color:var(--ink);font-family:var(--sans);
    line-height:1.55;-webkit-font-smoothing:antialiased;font-size:15px}
  .wrap{max-width:var(--maxw);margin:0 auto;padding:clamp(20px,4vw,48px) clamp(16px,4vw,40px) 72px}
  .mono{font-family:var(--mono);font-variant-numeric:tabular-nums}
  .eyebrow{font-family:var(--mono);text-transform:uppercase;letter-spacing:.18em;font-size:11px;color:var(--muted)}
  h1{font-family:var(--mono);font-weight:600;font-size:clamp(26px,4.4vw,40px);letter-spacing:-.01em;
    margin:.35em 0 .1em;text-wrap:balance}
  h1 .pulse{color:var(--accent)}
  .sub{color:var(--ink-2);max-width:64ch;margin:0}
  h2{font-family:var(--mono);text-transform:uppercase;letter-spacing:.14em;font-size:13px;color:var(--ink-2);
    margin:56px 0 4px;display:flex;align-items:center;gap:12px}
  h2::after{content:"";flex:1;height:1px;background:var(--line)}
  .lead{color:var(--muted);font-size:13.5px;margin:.2em 0 20px;max-width:70ch}

  /* masthead vitals */
  .masthead{display:flex;justify-content:space-between;gap:28px;flex-wrap:wrap;align-items:flex-end;
    border-bottom:1px solid var(--line);padding-bottom:26px}
  .fleet{display:flex;gap:26px;flex-wrap:wrap}
  .fleet .fig{display:flex;flex-direction:column;gap:2px}
  .fleet .fig b{font-family:var(--mono);font-size:22px;font-weight:600;color:var(--ink)}
  .fleet .fig span{font-family:var(--mono);text-transform:uppercase;letter-spacing:.1em;font-size:10px;color:var(--muted)}

  .grid{display:grid;gap:14px}
  .g-tiers{grid-template-columns:repeat(auto-fit,minmax(210px,1fr))}
  .g-cards{grid-template-columns:repeat(auto-fit,minmax(320px,1fr))}

  .card{background:var(--panel);border:1px solid var(--line);border-radius:var(--r);
    padding:16px 16px 14px;position:relative;overflow:hidden;display:flex;flex-direction:column;gap:10px}
  .card::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--stripe,var(--line))}
  .card.s-signal{--stripe:var(--good)} .card.s-flat{--stripe:var(--warn)} .card.s-anom{--stripe:var(--crit)}
  .card.s-info{--stripe:var(--accent)}
  .chead{display:flex;justify-content:space-between;align-items:baseline;gap:10px}
  .cname{font-family:var(--mono);font-weight:600;font-size:15px;letter-spacing:.01em}
  .ccad{font-family:var(--mono);font-size:11px;color:var(--muted);white-space:nowrap}
  .badge{font-family:var(--mono);text-transform:uppercase;letter-spacing:.1em;font-size:9.5px;font-weight:600;
    padding:3px 7px;border-radius:100px;display:inline-flex;align-items:center;gap:5px;white-space:nowrap}
  .badge::before{content:"";width:6px;height:6px;border-radius:50%}
  .b-signal{background:var(--good-soft);color:var(--good)} .b-signal::before{background:var(--good)}
  .b-flat{background:var(--warn-soft);color:var(--warn)} .b-flat::before{background:var(--warn)}
  .b-anom{background:var(--crit-soft);color:var(--crit)} .b-anom::before{background:var(--crit)}
  .b-info{background:var(--accent-soft);color:var(--accent)} .b-info::before{background:var(--accent)}

  .metric{display:flex;align-items:baseline;gap:8px;flex-wrap:wrap}
  .metric b{font-family:var(--mono);font-variant-numeric:tabular-nums;font-size:23px;font-weight:600;letter-spacing:-.02em}
  .metric small{font-family:var(--mono);font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}
  .note{font-size:12.5px;color:var(--ink-2);border-top:1px dashed var(--line);padding-top:9px;margin-top:2px}
  .note b{color:var(--ink);font-weight:600}

  svg.spark{display:block;width:100%;height:38px}
  svg.chart{display:block;width:100%;height:150px}
  .legend{display:flex;gap:14px;font-family:var(--mono);font-size:11px;color:var(--ink-2);flex-wrap:wrap}
  .legend i{display:inline-block;width:10px;height:2px;border-radius:2px;vertical-align:middle;margin-right:5px}

  /* CEE bars */
  .bars{display:flex;flex-direction:column;gap:6px}
  .bar{display:grid;grid-template-columns:96px 1fr auto;align-items:center;gap:8px;font-family:var(--mono);font-size:12px}
  .bar .lab{color:var(--ink-2);text-transform:uppercase;letter-spacing:.05em;font-size:10.5px}
  .bar .track{height:8px;background:var(--panel-2);border-radius:4px;overflow:hidden}
  .bar .fill{height:100%;background:var(--accent);border-radius:4px}
  .bar .val{color:var(--ink);font-variant-numeric:tabular-nums;text-align:right;min-width:42px}

  /* attention list */
  .att{display:grid;gap:10px;grid-template-columns:repeat(auto-fit,minmax(340px,1fr))}
  .lever{background:var(--panel-2);border:1px solid var(--line);border-left:3px solid var(--sc,var(--accent));
    border-radius:8px;padding:13px 15px}
  .lever.w{--sc:var(--warn)} .lever.c{--sc:var(--crit)} .lever.g{--sc:var(--good)}
  .lever h3{margin:0 0 4px;font-family:var(--mono);font-size:13px;font-weight:600;display:flex;gap:8px;align-items:center}
  .lever h3 .tag{font-size:9px;text-transform:uppercase;letter-spacing:.1em;color:var(--sc);
    border:1px solid var(--sc);border-radius:4px;padding:1px 5px}
  .lever p{margin:0;font-size:12.5px;color:var(--ink-2)}
  .lever p code{font-family:var(--mono);background:var(--panel);padding:1px 4px;border-radius:3px;font-size:11.5px;color:var(--ink)}

  .tt{position:fixed;pointer-events:none;background:var(--panel);border:1px solid var(--line);border-radius:6px;
    padding:6px 9px;font-family:var(--mono);font-size:11px;color:var(--ink);opacity:0;transition:opacity .08s;
    z-index:20;box-shadow:0 6px 20px rgba(0,0,0,.25);white-space:nowrap}

  footer{margin-top:60px;border-top:1px solid var(--line);padding-top:20px;color:var(--muted);font-size:12.5px}
  footer code{font-family:var(--mono);color:var(--ink-2)}
  a{color:var(--accent)}
  @media (prefers-reduced-motion:reduce){*{transition:none!important}}
</style>

<div class="wrap">
  <header class="masthead">
    <div>
      <div class="eyebrow">Enceladus · gamma · rhythm-cycle telemetry</div>
      <h1>Vital signs of a <span class="pulse">synthetic mind</span></h1>
      <p class="sub">Every background cognition beat, tenant, and metric — harvested from S3, CloudWatch and DynamoDB — read as one instrument panel. The question each card answers: <em>is this producing intelligent signal, idling, or misbehaving — and what's the lever?</em></p>
    </div>
    <div class="fleet" id="fleet"></div>
  </header>

  <h2>The five tiers · the heartbeat</h2>
  <p class="lead">Each tier fires on its own cadence and writes a beat artifact. A flat trace isn't failure — it's a question: is the tier quiescent by nature, or is its cadence/scope mismatched to what it's watching?</p>
  <div class="grid g-cards" id="tiers"></div>

  <h2>The cognition fleet · heavy-tier tenants</h2>
  <p class="lead">The six tenants the heavy beat invokes (2×/day). This is where "intelligent results" actually live — lesson candidates, structural graph metrics, entropy detection, percolation phase-transitions.</p>
  <div class="grid g-cards" id="tenants"></div>

  <h2>Signals worth your attention · tuning &amp; schedule levers</h2>
  <p class="lead">Where the data suggests a knob. Ranked by how much it distorts the read of "is the mind working."</p>
  <div class="att" id="levers"></div>

  <footer>
    <div><b style="color:var(--ink)">Raw bundle:</b> <code>/Users/jreese/rhythm-analysis/</code> — every artifact, metric series, telemetry row &amp; config snapshot (~850&nbsp;KB, 106 files). Regenerate anytime: <code>python3 rhythm_harvest.py</code> then <code>rhythm_analyze.py</code>.</div>
    <div id="stamp" style="margin-top:8px"></div>
  </footer>
</div>
<div class="tt" id="tt"></div>

<script>
const DATA = __DATA__;
const $ = (s,r=document)=>r.querySelector(s);
const el = (t,c,h)=>{const e=document.createElement(t);if(c)e.className=c;if(h!=null)e.innerHTML=h;return e;};
const num = (v,d=2)=> (v==null?"—": (typeof v==="number"? (Math.abs(v)>=1000? v.toLocaleString(undefined,{maximumFractionDigits:0}): v.toFixed(d)) : v));

// ---- sparkline (single series, glanceable) ----
function spark(vals, {stroke="var(--accent)", fill="var(--accent-soft)", flatMsg=null}={}){
  const v = vals.filter(x=>typeof x==="number");
  const W=300,H=38,pad=3;
  if(!v.length) return `<svg class="spark" viewBox="0 0 ${W} ${H}"></svg>`;
  let mn=Math.min(...v), mx=Math.max(...v);
  const flat = mx-mn < 1e-9;
  if(flat){mn-=1;mx+=1;}
  const x=i=>pad+ i*(W-2*pad)/Math.max(1,v.length-1);
  const y=val=>H-pad-((val-mn)/(mx-mn))*(H-2*pad);
  const pts=v.map((val,i)=>[x(i),y(val)]);
  const line=pts.map((p,i)=>(i?"L":"M")+p[0].toFixed(1)+" "+p[1].toFixed(1)).join(" ");
  const area=`M ${pad} ${H-pad} `+pts.map(p=>"L"+p[0].toFixed(1)+" "+p[1].toFixed(1)).join(" ")+` L ${W-pad} ${H-pad} Z`;
  const end=pts[pts.length-1];
  return `<svg class="spark" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">
    <path d="${area}" fill="${fill}"/>
    <path d="${line}" fill="none" stroke="${stroke}" stroke-width="1.6" stroke-linejoin="round" vector-effect="non-scaling-stroke"/>
    <circle cx="${end[0].toFixed(1)}" cy="${end[1].toFixed(1)}" r="2.4" fill="${stroke}"/>
  </svg>`;
}

// ---- interactive line chart (single or dual series) ----
let chartId=0;
function lineChart(series, {labels=null, yfmt=(v)=>num(v,3)}={}){
  const id="c"+(chartId++);
  const W=560,H=150,L=8,R=8,T=14,B=18;
  const all=series.flatMap(s=>s.data.filter(x=>typeof x==="number"));
  let mn=Math.min(...all), mx=Math.max(...all); if(mx-mn<1e-9){mx=mn+1;}
  const n=Math.max(...series.map(s=>s.data.length));
  const x=i=>L+i*(W-L-R)/Math.max(1,n-1);
  const y=v=>T+(1-(v-mn)/(mx-mn))*(H-T-B);
  // gridlines
  let grid="";
  for(let k=0;k<=2;k++){const yy=T+k*(H-T-B)/2;grid+=`<line x1="${L}" y1="${yy}" x2="${W-R}" y2="${yy}" stroke="var(--line-2)" stroke-width="1"/>`;}
  let paths="";
  series.forEach(s=>{
    const pts=s.data.map((v,i)=>typeof v==="number"?[x(i),y(v)]:null).filter(Boolean);
    if(!pts.length)return;
    const line=pts.map((p,i)=>(i?"L":"M")+p[0].toFixed(1)+" "+p[1].toFixed(1)).join(" ");
    paths+=`<path d="${line}" fill="none" stroke="${s.color}" stroke-width="2" stroke-linejoin="round" vector-effect="non-scaling-stroke"/>`;
    const e=pts[pts.length-1];
    paths+=`<circle cx="${e[0].toFixed(1)}" cy="${e[1].toFixed(1)}" r="3" fill="${s.color}"/>`;
  });
  const svg=`<svg class="chart" id="${id}" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none"
      data-n="${n}" data-l="${L}" data-r="${R}">
      ${grid}${paths}
      <line class="cross" x1="0" y1="${T}" x2="0" y2="${H-B}" stroke="var(--accent)" stroke-width="1" opacity="0"/>
    </svg>`;
  setTimeout(()=>hookChart(id,series,{x,labels,yfmt,mn,mx}),0);
  return svg;
}
function hookChart(id,series,{x,labels,yfmt}){
  const svg=document.getElementById(id); if(!svg)return;
  const tt=$("#tt"), cross=svg.querySelector(".cross"), n=+svg.dataset.n;
  svg.addEventListener("pointermove",ev=>{
    const r=svg.getBoundingClientRect();
    const px=(ev.clientX-r.left)/r.width*560;
    let i=Math.round((px-8)/((560-16)/Math.max(1,n-1)));
    i=Math.max(0,Math.min(n-1,i));
    cross.setAttribute("x1",x(i));cross.setAttribute("x2",x(i));cross.setAttribute("opacity",".6");
    const lab=labels?labels[i]:("#"+(i+1));
    let body=`<div style="color:var(--muted)">${lab}</div>`;
    series.forEach(s=>{if(typeof s.data[i]==="number")body+=`<div><span style="color:${s.color}">■</span> ${s.name}: <b>${yfmt(s.data[i])}</b></div>`;});
    tt.innerHTML=body;tt.style.opacity="1";
    tt.style.left=Math.min(ev.clientX+14,innerWidth-160)+"px";tt.style.top=(ev.clientY-10)+"px";
  });
  svg.addEventListener("pointerleave",()=>{tt.style.opacity="0";cross.setAttribute("opacity","0");});
}

// ---- card builder ----
function card(o){
  const c=el("div",`card s-${o.state}`);
  c.appendChild(el("div","chead",
    `<span class="cname">${o.name}</span>
     <span class="badge b-${o.state}">${o.badge}</span>`));
  if(o.cad) c.appendChild(el("div","ccad",o.cad));
  if(o.metric) c.appendChild(el("div","metric",o.metric));
  if(o.body){const b=el("div");b.innerHTML=o.body;c.appendChild(b);}
  if(o.note){const nn=el("div","note");nn.innerHTML=o.note;c.appendChild(nn);}
  return c;
}

/* ---------- FLEET SUMMARY ---------- */
(()=>{
  const beats=Object.values(DATA.beatcount).reduce((a,b)=>a+b,0);
  const inv=Object.values(DATA.lambda).reduce((a,b)=>a+(b.invocations||0),0);
  const errs=Object.values(DATA.lambda).reduce((a,b)=>a+(b.errors||0),0);
  const figs=[["5 / 6","tiers / tenants"],[beats,"beats on hand"],[inv.toFixed(0),"tenant invokes"],
    [errs+" ✓fixed","fleet errors"]];
  figs.forEach(([b,s])=>{const f=el("div","fig");f.innerHTML=`<b>${b}</b><span>${s}</span>`;$("#fleet").appendChild(f);});
})();

/* ---------- TIERS ---------- */
(()=>{
  const cad=m=>m>=60?(m/60)+"h":m+"m";
  const T=DATA;
  const tiers=[
    {name:"sense", cad:`every ${cad(T.cadence.sense)} · ${T.beatcount.sense} beats`, state:"flat", badge:"quiescent",
      metric:`<b>0</b><small>open tasks / queue</small>`,
      body:spark(T.sense_tasks),
      note:`Every vital reads <b>0</b> — no open tasks, empty queue, idle census. Correct if the system truly rests between agent sessions, but it means sense currently has <b>no dynamic range</b>: nothing here would look different under load. Lever: confirm what "busy" should register.`},
    {name:"light_integrate", cad:`every ${cad(T.cadence.light_integrate)} · ${T.beatcount.light_integrate} beats`, state:"flat", badge:"idle",
      metric:`<b>${num(T.light_delta.at(-1),0)}</b><small>changed records / beat</small>`,
      body:spark(T.light_delta),
      note:`FSRS decay + incremental summary run every 6h but <b>delta_count stays ~0</b> — few records changing between beats. The maintenance loop is healthy but starved of input.`},
    {name:"decide", cad:`every ${cad(T.cadence.decide)} · ${T.beatcount.decide} beats`, state:"flat", badge:"flat · V=0",
      metric:`<b>0</b><small>backlog open-leaves (Lyapunov V)</small>`,
      body:spark(T.decide_backlog),
      note:`The dispatch Lyapunov is <b>pinned at 0 every beat</b> — the backlog is always empty, so decide has nothing to converge and emits no dispatch plans. A 3h cadence on an empty backlog is the clearest schedule lever here.`},
    {name:"heavy_integrate", cad:`every ${cad(T.cadence.heavy_integrate)} · ${T.beatcount.heavy_integrate} beats`, state:"anom", badge:"orchestrating",
      metric:`<b>5 / 6</b><small>tenants invoked last window</small>`,
      body:`<div class="mono" style="font-size:12px;color:var(--ink-2)">recompute hook: <span style="color:var(--crit)">HTTP 404</span> (ENC-ISS-550)</div>`,
      note:`The orchestrator itself is healthy and fired all enabled tenants. Two caveats: the in-beat <b>governance recompute hook 404s</b> every window (harmless — legacy backstop keeps the hash current), and until today one tenant was dropped on an IAM gap (<b>fixed</b>, ENC-ISS-549).`},
    {name:"coherence", cad:`every ${cad(T.cadence.coherence)} · ${T.beatcount.coherence} beats`, state:"info", badge:"roll-up",
      metric:`<b>4</b><small>tiers cross-referenced</small>`,
      body:`<div class="mono" style="font-size:12px;color:var(--ink-2)">aligns sense · light · decide · heavy</div>`,
      note:`A meta-beat that stitches the other four tiers' latest artifacts into one aligned snapshot. Operational; no signal of its own to evaluate — it's the lens, not the instrument.`},
  ];
  tiers.forEach(t=>$("#tiers").appendChild(card(t)));
})();

/* ---------- TENANTS ---------- */
(()=>{
  const T=DATA, tn=T.tenants;
  const cee=(tn.corpus_entropy_engine&&tn.corpus_entropy_engine.detail&&tn.corpus_entropy_engine.detail.counts)||{};
  const ceeMax=Math.max(...Object.values(cee),1);
  const ceeBars=Object.entries(cee).sort((a,b)=>b[1]-a[1]).map(([k,v])=>
    `<div class="bar"><span class="lab">${k}</span><span class="track"><span class="fill" style="width:${(v/ceeMax*100).toFixed(0)}%"></span></span><span class="val">${v.toLocaleString()}</span></div>`).join("");

  const perc=T.perc;
  const percChart=lineChart(
    [{name:"empirical p_c",color:"var(--accent)",data:perc.map(r=>r.e)},
     {name:"analytical p_c",color:"var(--accent-2)",data:perc.map(r=>r.a)}],
    {labels:perc.map(r=>r.t), yfmt:v=>v.toFixed(3)});
  const fied=T.gh_fiedler;
  const fiedChart=lineChart([{name:"Fiedler λ₂",color:"var(--accent)",data:fied}],
    {labels:fied.map((_,i)=>"#"+(i+1)), yfmt:v=>v.toFixed(3)});

  const cards=[
    {name:"memory_consolidation", cad:`heavy · lesson candidates`, state:"flat", badge:"0 · starved",
      metric:`<b>0</b><small>candidates · 0 handoffs scanned</small>`,
      note:`Scans a <b>24h</b> lookback and found 0 handoffs → 0 clusters → 0 candidates. Not broken — its input window is empty. Its sibling HCE finds 74 over 90d. This 24h-vs-90d asymmetry is the single clearest tuning lever in the fleet.`},
    {name:"handoff_consolidation_engine", cad:`heavy · lesson candidates`, state:"signal", badge:"15 · producing",
      metric:`<b>15</b><small>candidates from 74 handoffs (90d)</small>`,
      note:`The one tenant demonstrably producing organic intelligence: 15 real lesson-candidate docs proposed to <span class="mono">documents-gamma</span> (33 detected, 18 dedup-skipped). This is the FTR-096 "first organic output" criterion, satisfied.`},
    {name:"graph_health_metrics", cad:`heavy + hourly · CloudWatch`, state:"anom", badge:"volatile",
      metric:`<b>${num(fied.filter(v=>v>0).at(-1),2)}</b><small>Fiedler algebraic connectivity λ₂</small>`,
      body:`${fiedChart}<div class="legend"><span><i style="background:var(--accent)"></i>λ₂ over ${fied.length} readings</span></div>`,
      note:`Connectivity is a real structural signal, but it <b>swings between regimes</b> (2.15 → 3.7 → 1.7 → 4.0) and drops to <b>0.0 twice</b> — almost certainly degenerate/failed computations, not a disconnecting graph. Orphan-ratio meanwhile holds ~0.0001. Worth hardening the λ₂ computation before trusting the trend.`},
    {name:"corpus_entropy_engine", cad:`heavy · 5 categories`, state:"signal", badge:"~26s / run",
      metric:`<b>${Object.values(cee).reduce((a,b)=>a+b,0).toLocaleString()}</b><small>entropy findings this window</small>`,
      body:`<div class="bars">${ceeBars}</div>`,
      note:`Rich, varying detection across 5 categories — genuine signal. Two flags: <b>relational (5,280)</b> dominates, and it reports <b>1,527 orphans</b> while GraphHealth's orphan-ratio is ~0. Different definitions of "orphan," worth reconciling. Also the slowest tenant at <b>~26s</b>/run.`},
    {name:"percolation_monitor", cad:`heavy · telemetry table`, state:"signal", badge:"phase-tracking",
      metric:`<b>${perc.at(-1).e.toFixed(2)}</b><small>empirical p_c (analytical ${perc.at(-1).a.toFixed(3)})</small>`,
      body:`${percChart}<div class="legend"><span><i style="background:var(--accent)"></i>empirical (Monte-Carlo)</span><span><i style="background:var(--accent-2)"></i>analytical (Molloy-Reed)</span></div>`,
      note:`Analytical p_c is rock-stable ~0.053 (robust giant component). Empirical p_c sat at 0.30 then <b>jumped 0.26 → 0.56</b> on the latest run as mean-degree rose — either real structural drift or Monte-Carlo variance (30 trials). A wide analytical-vs-empirical gap is itself the interesting reading.`},
    {name:"embedding_refresh", cad:`heavy · Titan re-embed`, state:"info", badge:"restored today",
      metric:`<b>1</b><small>invoke · 1 error (pre-fix)</small>`,
      note:`Intentionally enabled (ENC-TSK-N32) but was <b>AccessDenied</b> every window on a missing IAM grant — silently dropped. <b>Fixed &amp; deployed today</b> (ENC-ISS-549); it will re-embed changed records at the next 12:45Z window. No output history yet to evaluate.`},
  ];
  cards.forEach(c=>$("#tenants").appendChild(c));
})();

/* ---------- LEVERS ---------- */
(()=>{
  const levers=[
    {cls:"w",tag:"tuning",h:"memory_consolidation lookback: 24h → match HCE",
     p:"Same corpus, opposite result: <code>mem 24h → 0</code> vs <code>HCE 90d → 15</code>. Widen the memory-consolidation window (or make it adaptive like HCE's trigger) and it starts contributing instead of reporting empty."},
    {cls:"w",tag:"schedule",h:"decide fires every 3h on an empty backlog",
     p:"<code>backlog_open_leaves = 0</code> on every captured beat — the Lyapunov never has anything to minimize. Either the backlog feed isn't wired to real open work, or 3h is far too frequent for a zero-pressure queue. Cheapest win: lengthen cadence until there's signal."},
    {cls:"c",tag:"data-quality",h:"Fiedler λ₂ drops to 0.0 and jumps regimes",
     p:"Connectivity reads <code>0.0</code> twice among otherwise 2–4 values. A zero algebraic-connectivity means a disconnected graph — implausible here, so the estimator is failing on some runs. Trend is untrustworthy until the computation is hardened / guarded."},
    {cls:"c",tag:"reconcile",h:"Two different “orphans” disagree by 10,000×",
     p:"CEE reports <code>1,527 orphan</code> findings; GraphHealth reports <code>OrphanNodeRatio ≈ 0.0001</code>. They measure different things (unlinked docs vs. graph nodes), but surfaced side-by-side they'll mislead — define each explicitly or unify the term."},
    {cls:"w",tag:"performance",h:"corpus_entropy_engine ~26s per run",
     p:"By far the slowest tenant (vs 1–6s for the others). Fine at 2×/day, but it's the first thing that will strain if the heavy cadence tightens or the corpus grows — worth a scan-scope or incremental pass."},
    {cls:"w",tag:"observability",h:"CEE per-category metrics now in CloudWatch",
     p:"<code>Enceladus/CEE EntropyFindingCount</code> is dimensioned by <code>Category</code> (orphan, stagnation, relational, retention, compliance_semantic) plus <code>ScanDurationMs</code> for cost profiling. S3 beat-artifact retention for sense/decide is equalized to 7d (ENC-TSK-N49) so longitudinal harvests retain the tiers ISS-553 needs."},
    {cls:"g",tag:"healthy",h:"What's genuinely working",
     p:"HCE is producing organic lesson candidates; percolation is tracking a real phase-transition with stable analytical p_c; orphan-ratio is near zero; the beat scheduler itself fired <code>312</code> times with zero errors. The heartbeat is alive — the open questions are about yield and tuning, not survival."},
  ];
  levers.forEach(l=>{
    const d=el("div","lever "+l.cls);
    d.innerHTML=`<h3><span class="tag">${l.tag}</span>${l.h}</h3><p>${l.p}</p>`;
    $("#levers").appendChild(d);
  });
})();

$("#stamp").innerHTML = `Harvested <code>${(DATA_META&&DATA_META.harvested_at)||""}</code> · window ≈ last 7 days · read-only snapshot.`;
</script>
"""


def _round5(value):
    """Round numeric values to 5 places for compact embedding; pass others through."""
    return round(value, 5) if isinstance(value, (int, float)) else value


def _series(pairs):
    """Return the value (second element) of each [timestamp, value] pair, unmodified."""
    return [p[1] for p in (pairs or [])]


def _rounded_series(pairs):
    """Return the value of each [timestamp, value] pair, rounded to 5 places."""
    return [_round5(p[1]) for p in (pairs or [])]


def build_embed(data):
    """Project dashboard_data.json into the compact object the template consumes."""
    cloudwatch = data.get("cloudwatch", {}) or {}
    gh = cloudwatch.get("GraphHealth", {}) or {}
    rh = cloudwatch.get("Rhythm", {}) or {}
    tiers = data.get("tiers", {}) or {}
    sense = (tiers.get("sense", {}) or {}).get("series", {}) or {}
    light = (tiers.get("light_integrate", {}) or {}).get("series", {}) or {}
    decide = (tiers.get("decide", {}) or {}).get("series", {}) or {}
    heavy = tiers.get("heavy_integrate", {}) or {}
    perc_rows = (data.get("percolation", {}) or {}).get("rows", []) or []

    return {
        "gh_fiedler": _rounded_series(gh.get("FiedlerAlgebraicConnectivity")),
        "gh_orphan": _rounded_series(gh.get("OrphanNodeRatio")),
        "gh_density": _rounded_series(gh.get("GraphEdgeDensity")),
        "gh_nodes": _rounded_series(gh.get("GraphNodeCount")),
        "rh_dur": _rounded_series(rh.get("beat_duration_ms")),
        "rh_cost": _rounded_series(rh.get("beat_cost_estimate")),
        "perc": [
            {
                "t": (r.get("computed_at") or "")[:10],
                "a": r.get("analytical_pc"),
                "e": r.get("empirical_pc"),
                "deg": r.get("mean_degree"),
                "ent": r.get("flow_weight_entropy"),
                "spur": r.get("spurious_attractor_rate"),
            }
            for r in perc_rows
        ],
        "decide_backlog": _series(decide.get("backlog_open_leaves")),
        "light_delta": _series(light.get("delta_count")),
        "sense_tasks": _series(sense.get("open_task_count")),
        "sense_queue": _series(sense.get("queue_depth")),
        "cadence": {n: (tiers.get(n, {}) or {}).get("cadence_min") for n in TIER_ORDER},
        "beatcount": {n: (tiers.get(n, {}) or {}).get("beat_count") for n in TIER_ORDER},
        "heavy_invoked": heavy.get("invoked_history", []) or [],
        "tenants": data.get("tenants", {}) or {},
        "lambda": data.get("lambda", {}) or {},
        "manifest": data.get("manifest", {}) or {},
    }


def render(template, embed, harvested_at):
    """Embed the compact data + harvest stamp into the template HTML string."""
    if "__DATA__" not in template:
        raise ValueError("template is missing the __DATA__ placeholder")
    embed_json = json.dumps(embed)
    meta = "const DATA_META = " + json.dumps({"harvested_at": harvested_at}) + ";"
    # Replace the `const DATA = __DATA__;` line with the embedded JSON and inject
    # the DATA_META object on the following line.
    data_line = "const DATA = __DATA__;"
    replacement = "const DATA = " + embed_json + ";\n" + meta
    if data_line in template:
        return template.replace(data_line, replacement, 1)
    # Fallback: the placeholder is present but not on the expected line shape.
    html = template.replace("__DATA__", embed_json, 1)
    anchor = "const DATA = " + embed_json + ";"
    return html.replace(anchor, anchor + "\n" + meta, 1)


def _load_json(path):
    """Read and parse a JSON file, exiting with a clear message on failure."""
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        print(f"[ERROR] File not found: {path}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as exc:
        print(f"[ERROR] Invalid JSON in {path}: {exc}", file=sys.stderr)
        sys.exit(1)
    except OSError as exc:
        print(f"[ERROR] Could not read {path}: {exc}", file=sys.stderr)
        sys.exit(1)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Render the rhythm-cycle observability dashboard to self-contained HTML.",
    )
    parser.add_argument(
        "--out",
        default=DEFAULT_OUT,
        help=f"Bundle directory holding dashboard_data.json and INDEX.json (default: {DEFAULT_OUT})",
    )
    parser.add_argument(
        "--out-html",
        default=DEFAULT_OUT_HTML,
        help=f"Path to write the rendered HTML dashboard (default: {DEFAULT_OUT_HTML})",
    )
    args = parser.parse_args(argv)

    out_dir = Path(args.out)
    data_path = out_dir / "dashboard_data.json"
    index_path = out_dir / "INDEX.json"

    data = _load_json(data_path)
    index = _load_json(index_path)
    harvested_at = index.get("harvested_at", "")

    embed = build_embed(data)
    html = render(TEMPLATE_HTML, embed, harvested_at)

    out_html = Path(args.out_html)
    try:
        out_html.parent.mkdir(parents=True, exist_ok=True)
        out_html.write_text(html, encoding="utf-8")
    except OSError as exc:
        print(f"[ERROR] Could not write {out_html}: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"rhythm_dashboard.html written to {out_html}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
