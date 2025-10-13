# -*- coding: utf-8 -*-
"""
Report Generation Utilities for Phishing Detection Module
Creates comprehensive HTML summary reports with statistics and visualizations
"""

import os
import time
from java.util.logging import Level


class ReportGenerator:
    """Generates comprehensive HTML reports for URL phishing analysis"""
    
    def __init__(self, module_instance):
        """Initialize with reference to main module instance"""
        self.module = module_instance
        
    def generate_summary_report(self):
        """Generate an HTML summary report with statistics and charts and add it to Reports."""
        try:
            module_name = getattr(getattr(self.module, '__class__', object), 'moduleName', None) or "Comprehensive URL Phishing Extractor"
            # Aggregate stats
            total_urls = self.module.url_count
            # Classification counts
            classification_counts = {}
            for item in self.module.extracted_urls:
                label = item.get('classification', '')
                label = label if label and label.strip() else 'PENDING'
                classification_counts[label] = classification_counts.get(label, 0) + 1
            # Browser counts already maintained
            browser_counts = dict(self.module.browser_counts)
            # Top domains
            domain_counts = {}
            for item in self.module.extracted_urls:
                domain = item.get('domain', '') or ''
                if domain:
                    domain_counts[domain] = domain_counts.get(domain, 0) + 1
            top_domains = sorted(domain_counts.items(), key=lambda kv: kv[1], reverse=True)[:15]
            # Activity over time (per day)
            per_day_counts = {}
            for item in self.module.extracted_urls:
                ts = int(item.get('timestamp', 0) or 0)
                if ts > 0:
                    day = time.strftime('%Y-%m-%d', time.gmtime(ts))
                    per_day_counts[day] = per_day_counts.get(day, 0) + 1
            day_series = sorted(per_day_counts.items(), key=lambda kv: kv[0])
            # Activity heatmap (weekday x hour UTC)
            heatmap_counts = [[0 for _ in range(24)] for __ in range(7)]  # 0=Mon .. 6=Sun
            for item in self.module.extracted_urls:
                ts = int(item.get('timestamp', 0) or 0)
                if ts > 0:
                    tm = time.gmtime(ts)
                    w = tm.tm_wday  # 0..6 Mon..Sun
                    h = tm.tm_hour  # 0..23
                    if 0 <= w <= 6 and 0 <= h <= 23:
                        heatmap_counts[w][h] += 1
            # Prepare JS-friendly arrays
            def js_array_str(values):
                return '[' + ','.join(values) + ']'
            # Classification chart data
            class_labels = [k for k, _ in sorted(classification_counts.items(), key=lambda kv: kv[0])]
            class_values = [classification_counts[k] for k in class_labels]
            # Browser chart data
            browser_labels = [k for k, _ in sorted(browser_counts.items(), key=lambda kv: kv[0])]
            browser_values = [browser_counts[k] for k in browser_labels]
            # Per-browser classification breakdown (stacked bar)
            per_browser_class = {}
            encountered_classes = set()
            for item in self.module.extracted_urls:
                b = item.get('browser', '') or ''
                c = (item.get('classification', '') or '').strip().upper() or 'PENDING'
                encountered_classes.add(c)
                if b not in per_browser_class:
                    per_browser_class[b] = {}
                per_browser_class[b][c] = per_browser_class[b].get(c, 0) + 1
            # Order classes: phishing first
            preferred_order = ['PHISHING', 'SUSPICIOUS', 'MALICIOUS', 'PHISH', 'MALWARE', 'SAFE', 'PENDING', 'UNKNOWN', 'ERROR']
            class_labels_ordered = [c for c in preferred_order if c in encountered_classes]
            for c in sorted(list(encountered_classes)):
                if c not in class_labels_ordered:
                    class_labels_ordered.append(c)
            # Build series aligned with browser_labels
            stacked_series = []  # list per class: [counts per browser]
            for c in class_labels_ordered:
                row = []
                for b in browser_labels:
                    row.append(per_browser_class.get(b, {}).get(c, 0))
                stacked_series.append(row)
            # Top domains data
            domain_labels = [d for d, _ in top_domains]
            domain_values = [c for _, c in top_domains]
            # Heatmap labels
            weekday_labels = ['Mon','Tue','Wed','Thu','Fri','Sat','Sun']
            # Suspicious domains for word cloud (fallback to top domains)
            suspicious_set = set(['PHISHING','SUSPICIOUS','MALICIOUS','PHISH','MALWARE'])
            suspicious_domain_counts = {}
            for item in self.module.extracted_urls:
                lbl = (item.get('classification','') or '').strip().upper()
                d = item.get('domain','') or ''
                if not d:
                    continue
                if lbl in suspicious_set:
                    suspicious_domain_counts[d] = suspicious_domain_counts.get(d, 0) + 1
            if suspicious_domain_counts:
                cloud_pairs = sorted(suspicious_domain_counts.items(), key=lambda kv: kv[1], reverse=True)[:50]
            else:
                cloud_pairs = top_domains[:50]
            cloud_words = [d for d, _ in cloud_pairs]
            cloud_values = [c for _, c in cloud_pairs]
            # Report paths
            reports_dir = self.module.currentCase.getReportDirectory()
            report_folder = os.path.join(reports_dir, 'URL_Phishing_Report')
            try:
                if not os.path.exists(report_folder):
                    os.makedirs(report_folder)
            except Exception:
                pass
            report_file = os.path.join(report_folder, 'url_phishing_summary.html')
            # Build HTML content (uses Chart.js CDN for simplicity)
            html = []
            html.append('<!DOCTYPE html>')
            html.append('<html lang="en">')
            html.append('<head>')
            html.append('<meta charset="utf-8"/>')
            html.append('<meta name="viewport" content="width=device-width, initial-scale=1"/>')
            html.append('<title>URL Phishing Analysis Summary</title>')
            html.append('<style>')
            html.append('*{box-sizing:border-box}')
            html.append('body{font-family:"Segoe UI",Roboto,Helvetica,Arial,sans-serif;margin:0;padding:12px;background:#f5f5f5;color:#333333;line-height:1.5}')
            html.append('.container{max-width:1400px;margin:0 auto}')
            html.append('.header{background:#2c2c2c;color:white;padding:20px;border-radius:4px;margin-bottom:20px;box-shadow:0 2px 4px rgba(0,0,0,0.1)}')
            html.append('.header h1{margin:0;font-size:28px;font-weight:700}')
            html.append('.header .subtitle{margin:8px 0 0 0;opacity:0.9;font-size:16px}')
            html.append('.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:20px}')
            html.append('.stat-card{background:white;padding:20px;border-radius:4px;box-shadow:0 2px 4px rgba(0,0,0,0.05);border-left:4px solid #666666;transition:transform 0.2s,box-shadow 0.2s}')
            html.append('.stat-card:hover{transform:translateY(-2px);box-shadow:0 4px 8px rgba(0,0,0,0.1)}')
            html.append('.stat-card h3{margin:0 0 8px 0;font-size:14px;color:#666666;text-transform:uppercase;letter-spacing:0.5px}')
            html.append('.stat-card .value{font-size:32px;font-weight:700;color:#333333;margin:0}')
            html.append('.stat-card .subtext{font-size:12px;color:#666666;margin-top:4px}')
            html.append('.charts-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(350px,1fr));gap:20px;margin-bottom:20px}')
            html.append('.chart-card{background:white;padding:20px;border-radius:4px;box-shadow:0 2px 4px rgba(0,0,0,0.05);transition:box-shadow 0.2s}')
            html.append('.chart-card:hover{box-shadow:0 4px 8px rgba(0,0,0,0.1)}')
            html.append('.chart-card h2{margin:0 0 16px 0;font-size:18px;color:#333333;font-weight:600}')
            html.append('.chart-card canvas{max-width:100%;height:auto}')
            html.append('.full-width{grid-column:1/-1}')
            html.append('.table-card{background:white;padding:20px;border-radius:4px;box-shadow:0 2px 4px rgba(0,0,0,0.05);margin-bottom:20px}')
            html.append('.table-card h2{margin:0 0 16px 0;font-size:18px;color:#333333;font-weight:600}')
            html.append('table{width:100%;border-collapse:collapse;margin-top:8px;font-size:14px}')
            html.append('th,td{padding:12px 16px;text-align:left;border-bottom:1px solid #e0e0e0}')
            html.append('th{background:#f8f8f8;font-weight:600;color:#555555;font-size:12px;text-transform:uppercase;letter-spacing:0.5px}')
            html.append('tr:hover{background:#f8f8f8}')
            html.append('td:first-child{font-weight:500}')
            html.append('.muted{color:#666666;font-size:13px;font-style:italic}')
            html.append('.legend{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}')
            html.append('.legend-item{display:inline-flex;align-items:center;gap:6px;padding:6px 12px;border:1px solid #e0e0e0;border-radius:4px;background:#f8f8f8;cursor:pointer;font-size:12px;transition:all 0.2s}')
            html.append('.legend-item:hover{background:#e8e8e8;transform:translateY(-1px)}')
            html.append('.swatch{width:12px;height:12px;border-radius:2px;display:inline-block}')
            html.append('.tooltip{position:fixed;z-index:9999;background:#333333;color:white;padding:8px 12px;border-radius:4px;font-size:12px;pointer-events:none;opacity:0;transform:translate(-50%,-120%);transition:opacity 0.2s;box-shadow:0 4px 6px rgba(0,0,0,0.1)}')
            html.append('.badge{display:inline-block;padding:4px 8px;border-radius:4px;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px}')
            html.append('.badge-phishing{background:#ffe6e6;color:#cc0000}')
            html.append('.badge-suspicious{background:#fff2cc;color:#b8860b}')
            html.append('.badge-safe{background:#e6ffe6;color:#006600}')
            html.append('.badge-pending{background:#f0f0f0;color:#666666}')
            html.append('@media (max-width:768px){body{padding:8px}.charts-grid{grid-template-columns:1fr}.stats-grid{grid-template-columns:repeat(2,1fr)}.header h1{font-size:24px}.stat-card .value{font-size:28px}}')
            html.append('</style>')
            html.append('</head>')
            html.append('<body>')
            html.append('<div class="container">')
            html.append('<div class="header">')
            html.append('<h1>URL Phishing Analysis Summary</h1>')
            html.append('<p class="subtitle">Comprehensive analysis of browser URLs for phishing detection</p>')
            html.append('</div>')
            
            # Compact stats grid
            html.append('<div class="stats-grid">')
            html.append('<div class="stat-card"><h3>Total URLs</h3><div class="value">' + str(total_urls) + '</div><div class="subtext">Extracted from browsers</div></div>')
            html.append('<div class="stat-card"><h3>Unique Domains</h3><div class="value">' + str(len(self.module.domain_set)) + '</div><div class="subtext">Distinct websites</div></div>')
            html.append('<div class="stat-card"><h3>Browsers Analyzed</h3><div class="value">' + str(len(browser_counts)) + '</div><div class="subtext">Different browsers</div></div>')
            html.append('<div class="stat-card"><h3>Phishing Detected</h3><div class="value">' + str(sum(1 for item in self.module.extracted_urls if (item.get('classification', '').strip().upper() in ['PHISHING', 'SUSPICIOUS', 'MALICIOUS', 'PHISH', 'MALWARE']))) + '</div><div class="subtext">Suspicious URLs</div></div>')
            html.append('</div>')
            
            # Charts grid with 3-column layout
            html.append('<div class="charts-grid">')
            html.append('<div class="chart-card"><h2>URLs per Browser</h2><canvas id="browserChart" height="200"></canvas></div>')
            html.append('<div class="chart-card"><h2>Classification Distribution</h2><canvas id="classChart" height="200"></canvas></div>')
            html.append('<div class="chart-card"><h2>Classification Breakdown by Browser</h2><canvas id="stackedChart" height="200"></canvas><div id="stackedLegend" class="legend"></div><div class="muted">Each browser bar shows classification segments</div></div>')
            html.append('</div>')
            
            # Word cloud as full-width section
            html.append('<div class="charts-grid">')
            html.append('<div class="chart-card full-width"><h2>Domain Frequency Cloud</h2><canvas id="wordCloud" height="250"></canvas><div class="muted">Domain size represents frequency. Shows suspicious domains when available, otherwise top domains.</div></div>')
            html.append('</div>')
            # Detected phishing sites section (will populate when model is integrated)
            try:
                def esc(x):
                    try:
                        return str(x).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                    except Exception:
                        return ''
                phishing_like_labels = set([
                    'PHISHING', 'SUSPICIOUS', 'MALICIOUS', 'PHISH', 'MALWARE'
                ])
                detected_phishing = []
                for item in self.module.extracted_urls:
                    lbl = (item.get('classification') or '').strip()
                    if lbl and lbl.upper() in phishing_like_labels:
                        detected_phishing.append(item)
                # Sort newest first
                detected_phishing.sort(key=lambda it: int(it.get('timestamp') or 0), reverse=True)
                html.append('<div class="table-card"><h2>Detected Phishing Sites</h2>')
                if detected_phishing:
                    html.append('<table><thead><tr><th>URL</th><th>Domain</th><th>Classification</th><th>Last Seen</th></tr></thead><tbody>')
                    max_rows = 200
                    for idx, it in enumerate(detected_phishing):
                        if idx >= max_rows:
                            break
                        ts = int(it.get('timestamp') or 0)
                        seen = time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(ts)) if ts > 0 else '-'
                        classification = (it.get('classification', '') or '').strip().upper()
                        badge_class = 'badge-pending'
                        if classification in ['PHISHING', 'PHISH']:
                            badge_class = 'badge-phishing'
                        elif classification in ['SUSPICIOUS', 'MALICIOUS', 'MALWARE']:
                            badge_class = 'badge-suspicious'
                        elif classification == 'SAFE':
                            badge_class = 'badge-safe'
                        
                        html.append('<tr><td style="max-width:300px;word-break:break-all">' + esc(it.get('url','')) + '</td><td>' + esc(it.get('domain','')) + '</td><td><span class="badge ' + badge_class + '">' + esc(it.get('classification','')) + '</span></td><td>' + esc(seen) + '</td></tr>')
                    if len(detected_phishing) > max_rows:
                        html.append('<tr><td colspan="4" class="muted">Showing first ' + str(max_rows) + ' results...</td></tr>')
                    html.append('</tbody></table>')
                else:
                    html.append('<div class="muted">No phishing sites detected yet. This section will populate once the phishing model is integrated or classifications are provided.</div>')
                html.append('</div>')
            except Exception:
                # Fail-safe: do not block report generation if this section fails
                pass
            # Top domains table
            html.append('<div class="table-card"><h2>Top Domains</h2>')
            html.append('<table><thead><tr><th>Domain</th><th>URL Count</th></tr></thead><tbody>')
            for d, c in top_domains:
                html.append('<tr><td>' + d + '</td><td>' + str(c) + '</td></tr>')
            html.append('</tbody></table></div>')
            
            html.append('</div>')  # Close container
            # Charts script (no external dependencies)
            html.append('<script>')
            html.append('(function(){')
            html.append('function $(id){return document.getElementById(id)};function makeTip(){let t=document.createElement("div");t.className="tooltip";document.body.appendChild(t);return t}const tip=makeTip();function showTip(text,x,y){tip.textContent=text;tip.style.left=x+"px";tip.style.top=y+"px";tip.style.opacity=1}function hideTip(){tip.style.opacity=0}function within(mx,my,x,y,w,h){return mx>=x&&mx<=x+w&&my>=y&&my<=y+h}function drawValue(ctx,x,y,text){ctx.save();ctx.fillStyle="#111";ctx.font="11px Segoe UI";ctx.textAlign="center";ctx.textBaseline="bottom";ctx.fillText(text,x,y-3);ctx.restore()}')
            html.append('function drawBar(id, labels, data, color){const c=$(id);if(!c){return}const ctx=c.getContext("2d");const w=c.width;const h=c.height;const pad=28;const max=Math.max(1, Math.max.apply(null, data));const barW=(w - pad*2)/Math.max(1, data.length);ctx.clearRect(0,0,w,h);ctx.font="11px Segoe UI";ctx.textAlign="center";ctx.textBaseline="top";const meta=[];for(let i=0;i<data.length;i++){const val=data[i];const x=pad + i*barW + barW*0.1;const bw=barW*0.8;const bh=(h - pad*2)*(val/max);const y=h - pad - bh;ctx.fillStyle=color||"#4f46e5";ctx.fillRect(x,y,bw,bh);drawValue(ctx,x+bw/2,y,String(val));const lbl=labels[i]||"";ctx.fillStyle="#444";ctx.save();ctx.translate(x+bw/2,h-pad+3);ctx.rotate(-Math.PI/6);ctx.fillText(lbl,0,0);ctx.restore();meta.push({x:x,y:y,w:bw,h:bh,label:lbl,val:val})}c.onmousemove=function(ev){const r=c.getBoundingClientRect();const mx=ev.clientX-r.left;const my=ev.clientY-r.top;let hit=null;for(const m of meta){if(within(mx,my,m.x,m.y,m.w,m.h)){hit=m;break}}if(hit){showTip(hit.label+": "+hit.val,ev.clientX,ev.clientY)}else{hideTip()}};c.onmouseleave=hideTip;return {meta:meta}}')
            html.append('function drawLine(id, labels, data, stroke, fill){const c=$(id);if(!c){return}const ctx=c.getContext("2d");const w=c.width;const h=c.height;const pad=34;const max=Math.max(1, Math.max.apply(null, data));const min=0;ctx.clearRect(0,0,w,h);ctx.lineWidth=2;ctx.strokeStyle=stroke||"#0ea5e9";ctx.fillStyle=fill||"rgba(14,165,233,0.15)";const pts=[];for(let i=0;i<data.length;i++){const x=pad + (w - pad*2)*(i/Math.max(1,(data.length-1)));const y=h - pad - (h - pad*2)*((data[i]-min)/(max-min));pts.push({x:x,y:y,val:data[i],label:labels[i]||""})}if(pts.length){ctx.beginPath();ctx.moveTo(pts[0].x,pts[0].y);for(let i=1;i<pts.length;i++){ctx.lineTo(pts[i].x,pts[i].y)}ctx.stroke();ctx.beginPath();ctx.moveTo(pts[0].x,h-pad);for(let i=0;i<pts.length;i++){ctx.lineTo(pts[i].x,pts[i].y)}ctx.lineTo(pts[pts.length-1].x,h-pad);ctx.closePath();ctx.fill();ctx.fillStyle="#0ea5e9";for(const p of pts){ctx.beginPath();ctx.arc(p.x,p.y,3,0,Math.PI*2);ctx.fill();drawValue(ctx,p.x,p.y,String(p.val))}ctx.fillStyle="#444";ctx.font="12px Segoe UI";ctx.textAlign="center";ctx.textBaseline="top";for(let i=0;i<labels.length;i++){const lbl=labels[i]||"";ctx.save();ctx.translate(pts[i].x,h-pad+4);ctx.rotate(-Math.PI/6);ctx.fillText(lbl,0,0);ctx.restore();}}c.onmousemove=function(ev){const r=c.getBoundingClientRect();const mx=ev.clientX-r.left;const my=ev.clientY-r.top;let closest=null;let dmin=1e9;for(const p of pts){const d=Math.hypot(mx-p.x,my-p.y);if(d<8&&d<dmin){dmin=d;closest=p}}if(closest){showTip(closest.label+": "+closest.val,ev.clientX,ev.clientY)}else{hideTip()}};c.onmouseleave=hideTip;return {points:pts}}')
            html.append('function drawDoughnut(id, labels, data, colors){const c=$(id);if(!c){return}const ctx=c.getContext("2d");const w=c.width;const h=c.height;const cx=w/2;const cy=h/2;const r=Math.min(w,h)/2 - 10;const total=data.reduce((a,b)=>a+b,0)||1;let start=-Math.PI/2;ctx.clearRect(0,0,w,h);const arcs=[];for(let i=0;i<data.length;i++){const val=data[i];const angle=2*Math.PI*(val/total);ctx.beginPath();ctx.moveTo(cx,cy);ctx.arc(cx,cy,r,start,start+angle);ctx.closePath();ctx.fillStyle=(colors&&colors[i%colors.length])||"#4f46e5";ctx.fill();arcs.push({start:start,end:start+angle,val:val,label:labels[i]||"",color:((colors&&colors[i%colors.length])||"#4f46e5")});start+=angle}const ir=r*0.6;ctx.globalCompositeOperation="destination-out";ctx.beginPath();ctx.arc(cx,cy,ir,0,2*Math.PI);ctx.fill();ctx.globalCompositeOperation="source-over";ctx.fillStyle="#222";ctx.font="12px Segoe UI";ctx.textAlign="center";ctx.textBaseline="middle";ctx.fillText("Total: "+total,cx,cy);const legend=document.createElement("div");legend.className="legend";const hidden=new Array(data.length).fill(false);function redraw(){ctx.clearRect(0,0,w,h);let total2=0;for(let i=0;i<data.length;i++){if(!hidden[i]) total2+=data[i]}let s=-Math.PI/2;arcs.length=0;for(let i=0;i<data.length;i++){const val=hidden[i]?0:data[i];const angle=2*Math.PI*((val)/(total2||1));if(val>0){ctx.beginPath();ctx.moveTo(cx,cy);ctx.arc(cx,cy,r,s,s+angle);ctx.closePath();ctx.fillStyle=((colors&&colors[i%colors.length])||"#4f46e5");ctx.fill();arcs.push({start:s,end:s+angle,val:val,label:labels[i]||"",color:((colors&&colors[i%colors.length])||"#4f46e5")});}s+=angle}ctx.globalCompositeOperation="destination-out";ctx.beginPath();ctx.arc(cx,cy,ir,0,2*Math.PI);ctx.fill();ctx.globalCompositeOperation="source-over";ctx.fillStyle="#222";ctx.font="12px Segoe UI";ctx.textAlign="center";ctx.textBaseline="middle";ctx.fillText("Total: "+(total2||0),cx,cy)}for(let i=0;i<labels.length;i++){const item=document.createElement("span");item.className="legend-item";const sw=document.createElement("span");sw.className="swatch";sw.style.backgroundColor=(colors&&colors[i%colors.length])||"#4f46e5";const lb=document.createElement("span");lb.textContent=labels[i]+" ("+(data[i]||0)+")";item.appendChild(sw);item.appendChild(lb);item.onclick=function(){hidden[i]=!hidden[i];sw.style.opacity=hidden[i]?0.3:1;lb.style.textDecoration=hidden[i]?"line-through":"none";redraw()};legend.appendChild(item)}c.parentNode.appendChild(legend);c.onmousemove=function(ev){const rct=c.getBoundingClientRect();const mx=ev.clientX-rct.left;const my=ev.clientY-rct.top;const dx=mx-cx;const dy=my-cy;const a=Math.atan2(dy,dx);let ang=a;while(ang< -Math.PI/2){ang+=Math.PI*2}while(ang>3*Math.PI/2){ang-=Math.PI*2}const dist=Math.hypot(dx,dy);if(dist<ir||dist>r){hideTip();return}let hit=null;for(const ar of arcs){if(ang>=ar.start&&ang<=ar.end){hit=ar;break}}if(hit){showTip(hit.label+": "+hit.val,ev.clientX,ev.clientY)}else{hideTip()}};c.onmouseleave=hideTip;redraw();return {arcs:arcs}}')
            html.append('function toArray(x){try{return JSON.parse(x)}catch(e){return []}}')
            # Utilities for stacked bar and word cloud
            html.append('function randomColor(seed){const c=["#3b82f6","#10b981","#ef4444","#f59e0b","#06b6d4","#a855f7","#f97316","#0ea5e9","#64748b","#84cc16"];return c[seed % c.length]}')
            html.append('function drawStackedBar(id, labels, classes, series){const c=document.getElementById(id);if(!c){return}const ctx=c.getContext("2d");const w=c.width;const h=c.height;const pad=30;ctx.clearRect(0,0,w,h);ctx.font="11px Segoe UI";const bw=(w - pad*2)/Math.max(1,labels.length);const max=Math.max(1, ...labels.map((_,i)=>series.reduce((a,row)=>a+row[i],0)));const bars=[];for(let i=0;i<labels.length;i++){const x=pad+i*bw + bw*0.1;const innerW=bw*0.8;let y=h-pad;for(let k=0;k<classes.length;k++){const val=series[k][i]||0;const bh=(h - pad*2)*(val/max);y-=bh;ctx.fillStyle=randomColor(k);ctx.fillRect(x,y,innerW,bh);bars.push({x:x,y:y,w:innerW,h:bh,label:labels[i],cls:classes[k],val:val});if(bh>12){ctx.fillStyle="#111";ctx.textAlign="center";ctx.textBaseline="middle";ctx.fillText(String(val),x+innerW/2,y+bh/2)}}ctx.fillStyle="#444";ctx.save();ctx.translate(x+innerW/2,h-pad+3);ctx.rotate(-Math.PI/6);ctx.fillText(labels[i],0,0);ctx.restore()}c.onmousemove=function(ev){const r=c.getBoundingClientRect();const mx=ev.clientX-r.left;const my=ev.clientY-r.top;let hit=null;for(const b of bars){if(mx>=b.x&&mx<=b.x+b.w&&my>=b.y&&my<=b.y+b.h){hit=b;break}}if(hit){showTip(hit.label+" - "+hit.cls+": "+hit.val,ev.clientX,ev.clientY)}else{hideTip()}};c.onmouseleave=hideTip;const legend=document.getElementById("stackedLegend");if(legend){legend.innerHTML="";for(let k=0;k<classes.length;k++){const item=document.createElement("span");item.className="legend-item";const sw=document.createElement("span");sw.className="swatch";sw.style.backgroundColor=randomColor(k);const lb=document.createElement("span");lb.textContent=classes[k];item.appendChild(sw);item.appendChild(lb);legend.appendChild(item)}}return {bars:bars}}')
            html.append('function drawWordCloud(id, words, values){const c=document.getElementById(id);if(!c){return}const ctx=c.getContext("2d");const w=c.width;const h=c.height;ctx.clearRect(0,0,w,h);ctx.textAlign="center";ctx.textBaseline="middle";const max=Math.max(1, Math.max.apply(null, values));const min=Math.min.apply(null, values.concat([0]));const items=words.map((w,i)=>({text:w,val:values[i]||1,size:12+24*((values[i]||1)-min)/(max-min||1)})).sort((a,b)=>b.val-a.val);const placed=[];function collides(x,y,box){for(const p of placed){if(!(x+box.w<p.x||x>p.x+p.w||y+box.h<p.y||y>p.y+p.h)){return true}}return false}for(let i=0;i<items.length;i++){const it=items[i];ctx.font=Math.round(it.size)+"px Segoe UI";const m=ctx.measureText(it.text);const box={w:m.width+10,h:it.size+6};let angle=(i%2===0)?0:0;let radius=0,theta=0,placedOk=false;while(radius<Math.max(w,h)&&!placedOk){const x=w/2 + radius*Math.cos(theta) - box.w/2;const y=h/2 + radius*Math.sin(theta) - box.h/2;theta+=0.3;radius+=0.5;if(x<0||y<0||x+box.w>w||y+box.h>h) continue;if(!collides(x,y,box)){placedOk=true;placed.push({x:x,y:y,w:box.w,h:box.h,text:it.text,val:it.val,size:it.size})}}}for(const p of placed){ctx.font=Math.round(p.size)+"px Segoe UI";ctx.fillStyle="#111";ctx.fillText(p.text,p.x+p.w/2,p.y+p.h/2)}c.onmousemove=function(ev){const r=c.getBoundingClientRect();const mx=ev.clientX-r.left;const my=ev.clientY-r.top;let hit=null;for(const p of placed){if(mx>=p.x&&mx<=p.x+p.w&&my>=p.y&&my<=p.y+p.h){hit=p;break}}if(hit){showTip(hit.text+": "+hit.val,ev.clientX,ev.clientY)}else{hideTip()}};c.onmouseleave=hideTip;return {items:placed}}')
            html.append('const browserLabels=' + js_array_str(['"' + l.replace('"','\"') + '"' for l in browser_labels]) + ';')
            html.append('const browserValues=' + js_array_str([str(v) for v in browser_values]) + ';')
            html.append('const classLabels=' + js_array_str(['"' + l.replace('"','\"') + '"' for l in class_labels]) + ';')
            html.append('const classValues=' + js_array_str([str(v) for v in class_values]) + ';')
            # Data for stacked per-browser classification
            html.append('const stackedBrowsers=' + js_array_str(['"' + l.replace('"','\"') + '"' for l in browser_labels]) + ';')
            html.append('const stackedClasses=' + js_array_str(['"' + l + '"' for l in class_labels_ordered]) + ';')
            html.append('const stackedSeries=' + js_array_str(['[' + ','.join([str(v) for v in row]) + ']' for row in stacked_series]) + ';')
            # Data for word cloud
            html.append('const cloudWords=' + js_array_str(['"' + w.replace('"','\"') + '"' for w in cloud_words]) + ';')
            html.append('const cloudValues=' + js_array_str([str(v) for v in cloud_values]) + ';')
            html.append('function ready(fn){if(document.readyState!="loading"){fn()}else{document.addEventListener("DOMContentLoaded",fn)}}')
            html.append('ready(function(){drawBar("browserChart",browserLabels,browserValues,"#3b82f6");drawDoughnut("classChart",classLabels,classValues,["#10b981","#ef4444","#f59e0b","#6366f1","#06b6d4","#a855f7","#f97316"]);drawStackedBar("stackedChart",stackedBrowsers,stackedClasses,stackedSeries);drawWordCloud("wordCloud",cloudWords,cloudValues);});')
            html.append('})();')
            html.append('</script>')
            html.append('</body></html>')
            # Write file
            with open(report_file, 'w') as f:
                f.write('\n'.join(html))
            # Register report so it shows in Autopsy Reports tree
            try:
                self.module.currentCase.addReport(report_file, module_name, 'URL Phishing Summary')
            except Exception as e:
                self.module.log(Level.INFO, 'Unable to register report: ' + str(e))
        except Exception as e:
            self.module.log(Level.WARNING, 'Failed to generate summary report: ' + str(e))