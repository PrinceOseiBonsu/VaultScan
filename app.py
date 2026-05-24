# app.py
# VaultScan - Personal Security Audit Tool

from flask import Flask, render_template, jsonify, redirect, url_for, send_file
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, HRFlowable, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
import threading
import os
import io
from scanner.system_info import get_system_info
from scanner.port_scanner import scan_ports
from scanner.vulnerability import run_vulnerability_scan

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "vaultscan-2026-prince")

scan_results = {}
scan_status = {"running": False, "complete": False}

def run_full_scan():
    global scan_results, scan_status
    scan_status["running"] = True
    scan_status["complete"] = False

    try:
        scan_status["step"] = "Gathering system information..."
        scan_results["system"] = get_system_info()

        scan_status["step"] = "Scanning open ports..."
        scan_results["ports"] = scan_ports("127.0.0.1")

        scan_status["step"] = "Checking vulnerabilities..."
        scan_results["vulnerabilities"] = run_vulnerability_scan()

        scan_results["score"] = scan_results["vulnerabilities"]["score"]
        scan_results["risk_level"] = scan_results["vulnerabilities"]["risk_level"]

        scan_status["complete"] = True
        scan_status["running"] = False
        scan_status["step"] = "Scan complete!"

    except Exception as e:
        scan_status["running"] = False
        scan_status["error"] = str(e)

def generate_pdf_report(system, ports, vulns, score, risk_level):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=0.6*inch,
        leftMargin=0.6*inch,
        topMargin=0.6*inch,
        bottomMargin=0.6*inch
    )

    styles = {
        'title': ParagraphStyle('title', fontName='Helvetica-Bold', fontSize=18, spaceAfter=4),
        'subtitle': ParagraphStyle('subtitle', fontName='Helvetica', fontSize=9, spaceAfter=12, textColor=colors.grey),
        'section': ParagraphStyle('section', fontName='Helvetica-Bold', fontSize=11, spaceBefore=14, spaceAfter=6, textColor=colors.HexColor('#0f3460')),
        'normal': ParagraphStyle('normal', fontName='Helvetica', fontSize=9, spaceAfter=4),
        'bullet': ParagraphStyle('bullet', fontName='Helvetica', fontSize=9, leftIndent=16, firstLineIndent=-16, spaceAfter=4),
        'small': ParagraphStyle('small', fontName='Helvetica', fontSize=8, textColor=colors.grey),
    }

    story = []

    # Title
    story.append(Paragraph("VaultScan Security Audit Report", styles['title']))
    story.append(Paragraph(
        f"Generated: {system.get('scan_time', '')} | Host: {system.get('hostname', '')} | IP: {system.get('ip_address', '')}",
        styles['subtitle']
    ))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#e94560'), spaceAfter=10))

    # Score section
    story.append(Paragraph("SECURITY SCORE", styles['section']))

    score_color = colors.HexColor('#16a34a') if score >= 80 else \
                  colors.HexColor('#fbbf24') if score >= 60 else \
                  colors.HexColor('#dc2626')

    risk_colors = {
        'LOW': '#dcfce7',
        'MEDIUM': '#fef9c3',
        'HIGH': '#ffedd5',
        'CRITICAL': '#fee2e2'
    }
    risk_text_colors = {
        'LOW': '#16a34a',
        'MEDIUM': '#ca8a04',
        'HIGH': '#ea580c',
        'CRITICAL': '#dc2626'
    }

    bg_color = risk_colors.get(risk_level, '#f8fafc')
    text_color = risk_text_colors.get(risk_level, '#1a1a2e')

    score_data = [[
        Paragraph(
            f"<b>{score} / 100</b>",
            ParagraphStyle('score', fontName='Helvetica-Bold', fontSize=22,
                          textColor=score_color, alignment=TA_CENTER)
        ),
        Paragraph(
            f"<b>Risk Level: {risk_level}</b><br/><br/>"
            f"Firewall: {'✓ Protected' if not vulns['vulnerabilities']['firewall']['risk'] else '✗ At Risk'}     "
            f"Antivirus: {'✓ Protected' if not vulns['vulnerabilities']['antivirus']['risk'] else '✗ At Risk'}     "
            f"RDP: {'✓ Disabled' if not vulns['vulnerabilities']['remote_desktop']['risk'] else '✗ Exposed'}<br/>"
            f"Updates: {'✓ Current' if not vulns['vulnerabilities']['windows_updates']['risk'] else '✗ Outdated'}     "
            f"Shares: {'✓ OK' if not vulns['vulnerabilities']['open_shares']['risk'] else '✗ Review'}     "
            f"Password: {'✓ Strong' if not vulns['vulnerabilities']['password_policy']['risk'] else '✗ Weak'}",
            ParagraphStyle('scoreinfo', fontName='Helvetica', fontSize=9,
                          textColor=colors.HexColor('#1a1a2e'))
        )
    ]]

    score_table = Table(score_data, colWidths=[1.8*inch, 5.5*inch])
    score_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor(bg_color)),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#e2e8f0')),
        ('LINEAFTER', (0,0), (0,-1), 1, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0,0), (-1,-1), 14),
        ('BOTTOMPADDING', (0,0), (-1,-1), 14),
        ('LEFTPADDING', (0,0), (-1,-1), 14),
        ('RIGHTPADDING', (0,0), (-1,-1), 14),
    ]))
    story.append(score_table)
    story.append(Spacer(1, 6))

    # System Information
    story.append(Paragraph("SYSTEM INFORMATION", styles['section']))
    sys_data = [
        ['Operating System', f"{system.get('os', '')} {system.get('os_release', '')}"],
        ['Architecture', system.get('architecture', '')],
        ['Processor', f"{system.get('cpu_cores', '')} cores / {system.get('cpu_threads', '')} threads"],
        ['IP Address', system.get('ip_address', '')],
        ['Memory Usage', f"{system.get('used_memory', '')}GB / {system.get('total_memory', '')}GB ({system.get('memory_percent', '')}%)"],
        ['Disk Usage', f"{system.get('used_disk', '')}GB / {system.get('total_disk', '')}GB ({system.get('disk_percent', '')}%)"],
    ]
    sys_table = Table(sys_data, colWidths=[2*inch, 5.3*inch])
    sys_table.setStyle(TableStyle([
        ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 9),
        ('TEXTCOLOR', (0,0), (0,-1), colors.HexColor('#64748b')),
        ('ROWBACKGROUNDS', (0,0), (-1,-1), [colors.white, colors.HexColor('#f8fafc')]),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING', (0,0), (-1,-1), 10),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
    ]))
    story.append(sys_table)

    # Security Checks
    story.append(Paragraph("SECURITY CHECKS", styles['section']))
    vuln_data = vulns['vulnerabilities']
    checks = [
        ['Check', 'What It Does', 'Status', 'Result'],
        ['Firewall', 'Blocks unauthorized access to your computer',
         'Protected' if not vuln_data['firewall']['risk'] else 'At Risk',
         'PASS' if not vuln_data['firewall']['risk'] else 'FAIL'],
        ['Antivirus', 'Protects against viruses and malware',
         'Protected' if not vuln_data['antivirus']['risk'] else 'At Risk',
         'PASS' if not vuln_data['antivirus']['risk'] else 'FAIL'],
        ['Windows Updates', 'Keeps system patched against vulnerabilities',
         'Up to Date' if not vuln_data['windows_updates']['risk'] else 'Outdated',
         'PASS' if not vuln_data['windows_updates']['risk'] else 'FAIL'],
        ['Remote Desktop', 'Allows others to control your computer remotely',
         'Disabled' if not vuln_data['remote_desktop']['risk'] else 'Exposed',
         'PASS' if not vuln_data['remote_desktop']['risk'] else 'FAIL'],
        ['Network Shares', 'Folders shared with others on your network',
         'OK' if not vuln_data['open_shares']['risk'] else 'Review Needed',
         'PASS' if not vuln_data['open_shares']['risk'] else 'FAIL'],
        ['Password Policy', 'How strong your password requirements are',
         'Strong' if not vuln_data['password_policy']['risk'] else 'Weak',
         'PASS' if not vuln_data['password_policy']['risk'] else 'FAIL'],
    ]
    checks_table = Table(checks, colWidths=[1.3*inch, 2.8*inch, 1.5*inch, 0.7*inch])
    checks_table.setStyle(TableStyle([
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 8.5),
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f3460')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')]),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
    ]))
    story.append(checks_table)

    # Open Ports
    story.append(Paragraph(f"OPEN PORTS ({ports.get('total_open', 0)} found)", styles['section']))
    if ports.get('open_ports'):
        port_data = [['Port', 'Service', 'Status', 'Risk Reason']]
        for p in ports['open_ports']:
            port_data.append([
                str(p['port']),
                p['service'],
                'RISKY' if p['risk'] else 'SAFE',
                p['risk_reason'] or 'No known risk'
            ])
        port_table = Table(port_data, colWidths=[0.7*inch, 1.1*inch, 0.8*inch, 4.7*inch])
        port_table.setStyle(TableStyle([
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 8.5),
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f3460')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')]),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
            ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ]))
        story.append(port_table)
    else:
        story.append(Paragraph("No open ports detected — your system is well protected!", styles['normal']))

    # Recommendations
    story.append(Paragraph("WHAT YOU SHOULD DO", styles['section']))
    recs = []

    if vuln_data['firewall']['risk']:
        recs.append((
            "Turn On Your Firewall — URGENT",
            "Your firewall is off. Think of it as a security guard for your computer. Without it, anyone can try to connect to your computer.",
            "Click Start → Type 'Windows Security' → Click 'Firewall and Network Protection' → Turn on all three profiles"
        ))
    if vuln_data['antivirus']['risk']:
        recs.append((
            "Turn On Your Antivirus — URGENT",
            "Your antivirus is off. Without it, viruses and ransomware can infect your computer without you knowing.",
            "Click Start → Type 'Windows Security' → Click 'Virus and Threat Protection' → Turn on Real-time Protection"
        ))
    if vuln_data['password_policy']['risk']:
        recs.append((
            "Use a Stronger Password",
            "Your password settings are weak. A weak password is like a lock anyone can pick. Use at least 12 characters with numbers and symbols.",
            "Good example: MyDog$Fluffy2026! — Bad example: password123 (hackers guess this in seconds)"
        ))
    if vuln_data['open_shares']['risk']:
        recs.append((
            "Stop Sharing Your Folders",
            "Your computer is sharing folders with others on the network. Anyone on your network could access your files.",
            "Click Start → Type 'Control Panel' → Network and Sharing Center → Advanced sharing settings → Turn off file and printer sharing"
        ))
    if ports.get('total_risky', 0) > 0:
        recs.append((
            f"Close {ports['total_risky']} Dangerous Open Port(s)",
            "You have dangerous ports open. Think of ports like doors into your computer — these are known entry points for hackers and ransomware.",
            "Contact your school IT department or a trusted tech person to help close these ports safely."
        ))

    if recs:
        rec_data = [['#', 'Issue', 'What It Means', 'How To Fix It']]
        for i, (title, desc, fix) in enumerate(recs, 1):
            rec_data.append([str(i), title, desc, fix])
        rec_table = Table(rec_data, colWidths=[0.3*inch, 1.5*inch, 2.5*inch, 3.0*inch])
        rec_table.setStyle(TableStyle([
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#e94560')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#fff0f3')]),
            ('TOPPADDING', (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
            ('FONTNAME', (1,1), (1,-1), 'Helvetica-Bold'),
        ]))
        story.append(rec_table)
    else:
        story.append(Paragraph(
            "Great news! Your system looks well protected. Keep your Windows updated and continue using strong passwords to stay safe.",
            styles['normal']
        ))

    # Footer
    story.append(Spacer(1, 16))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#e2e8f0'), spaceAfter=8))
    story.append(Paragraph(
        "Generated by VaultScan · Built by Prince Osei Bonsu · Voorhees University · This report is for educational purposes only",
        ParagraphStyle('footer', fontName='Helvetica', fontSize=7.5, textColor=colors.grey, alignment=TA_CENTER)
    ))

    doc.build(story)
    buffer.seek(0)
    return buffer

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/scan")
def start_scan():
    global scan_results, scan_status
    scan_results = {}
    scan_status = {"running": False, "complete": False}
    thread = threading.Thread(target=run_full_scan)
    thread.daemon = True
    thread.start()
    return render_template("scanning.html")

@app.route("/status")
def scan_status_check():
    return jsonify(scan_status)

@app.route("/report")
def report():
    if not scan_results:
        return render_template("index.html")
    return render_template("report.html",
                           system=scan_results.get("system", {}),
                           ports=scan_results.get("ports", {}),
                           vulns=scan_results.get("vulnerabilities", {}),
                           score=scan_results.get("score", 0),
                           risk_level=scan_results.get("risk_level", "UNKNOWN"))

@app.route("/download-report")
def download_report():
    if not scan_results:
        return redirect(url_for('home'))
    buffer = generate_pdf_report(
        scan_results.get("system", {}),
        scan_results.get("ports", {}),
        scan_results.get("vulnerabilities", {}),
        scan_results.get("score", 0),
        scan_results.get("risk_level", "UNKNOWN")
    )
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"VaultScan_Report_{scan_results['system']['hostname']}.pdf",
        mimetype='application/pdf'
    )

import webbrowser
import threading

if __name__ == "__main__":
    def open_browser():
        import time
        time.sleep(1.5)
        webbrowser.open("http://127.0.0.1:5000")
    
    threading.Thread(target=open_browser, daemon=True).start()
    app.run(debug=False, use_reloader=False)