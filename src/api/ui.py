"""Cyber Security Command Center UI module rendering an ultra-sleek, immersive dark-mode frontend with dynamic v1.0-hardening5 integration."""

from __future__ import annotations


def render_cyber_ui_html() -> str:
    """Generate the interactive single-page Cyber Security Command Center web UI HTML."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ScamON - Cyber Threat Command Center</title>
    <!-- Fonts -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;700&family=Orbitron:wght@400;600;700;900&display=swap" rel="stylesheet">
    <!-- FontAwesome icons -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        :root {
            --bg-dark: #030712;
            --bg-card: rgba(10, 20, 38, 0.75);
            --bg-card-hover: rgba(16, 32, 58, 0.85);
            --border-cyan: rgba(0, 243, 255, 0.3);
            --border-red: rgba(255, 0, 85, 0.4);
            --border-amber: rgba(255, 183, 0, 0.4);
            --cyan-glow: #00f3ff;
            --cyan-dim: rgba(0, 243, 255, 0.15);
            --red-glow: #ff0055;
            --red-dim: rgba(255, 0, 85, 0.15);
            --amber-glow: #ffb700;
            --amber-dim: rgba(255, 183, 0, 0.15);
            --green-glow: #00ff88;
            --green-dim: rgba(0, 255, 136, 0.15);
            --text-main: #f1f5f9;
            --text-muted: #94a3b8;
            --text-cyber: #38bdf8;
            --font-head: 'Orbitron', sans-serif;
            --font-body: 'Inter', sans-serif;
            --font-code: 'JetBrains Mono', monospace;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            background-color: var(--bg-dark);
            color: var(--text-main);
            font-family: var(--font-body);
            min-height: 100vh;
            overflow-x: hidden;
            position: relative;
        }

        /* Matrix Canvas */
        #cyber-canvas {
            position: fixed;
            top: 0;
            left: 0;
            width: 100vw;
            height: 100vh;
            z-index: 0;
            pointer-events: none;
            opacity: 0.6;
        }

        .app-container {
            position: relative;
            z-index: 1;
            max-width: 1600px;
            margin: 0 auto;
            padding: 20px;
            display: flex;
            flex-direction: column;
            gap: 20px;
        }

        /* HUD Header */
        header.hud-header {
            background: rgba(6, 15, 30, 0.85);
            border: 1px solid var(--border-cyan);
            box-shadow: 0 0 20px rgba(0, 243, 255, 0.15);
            backdrop-filter: blur(12px);
            border-radius: 12px;
            padding: 16px 24px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            position: relative;
            flex-wrap: wrap;
            gap: 16px;
        }

        header.hud-header::before {
            content: '';
            position: absolute;
            top: -1px; left: 40px; right: 40px; height: 2px;
            background: linear-gradient(90deg, transparent, var(--cyan-glow), transparent);
        }

        .brand {
            display: flex;
            align-items: center;
            gap: 16px;
        }

        .brand-icon {
            width: 44px;
            height: 44px;
            background: radial-gradient(circle, rgba(0,243,255,0.2) 0%, rgba(3,7,18,0.8) 100%);
            border: 1px solid var(--cyan-glow);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 20px;
            color: var(--cyan-glow);
            box-shadow: 0 0 15px rgba(0, 243, 255, 0.4);
            animation: pulse-border 3s infinite alternate;
        }

        @keyframes pulse-border {
            0% { box-shadow: 0 0 10px rgba(0, 243, 255, 0.3); }
            100% { box-shadow: 0 0 22px rgba(0, 243, 255, 0.8); }
        }

        .brand-text h1 {
            font-family: var(--font-head);
            font-size: 20px;
            letter-spacing: 2px;
            color: #ffffff;
            text-shadow: 0 0 10px rgba(0, 243, 255, 0.5);
        }

        .brand-text p {
            font-size: 11px;
            color: var(--cyan-glow);
            font-family: var(--font-code);
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .hud-status-bar {
            display: flex;
            align-items: center;
            gap: 12px;
            flex-wrap: wrap;
        }

        .status-pill {
            display: flex;
            align-items: center;
            gap: 8px;
            font-family: var(--font-code);
            font-size: 11px;
            background: rgba(0, 243, 255, 0.08);
            border: 1px solid rgba(0, 243, 255, 0.25);
            padding: 5px 12px;
            border-radius: 20px;
            white-space: nowrap;
        }

        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--green-glow);
            box-shadow: 0 0 8px var(--green-glow);
            animation: blink 1.5s infinite;
        }

        .status-dot.disconnected {
            background: var(--red-glow);
            box-shadow: 0 0 8px var(--red-glow);
        }

        .status-dot.degraded {
            background: var(--amber-glow);
            box-shadow: 0 0 8px var(--amber-glow);
        }

        @keyframes blink {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.3; }
        }

        .hud-btn {
            background: linear-gradient(135deg, rgba(0,243,255,0.15), rgba(0,100,150,0.3));
            border: 1px solid var(--cyan-glow);
            color: #ffffff;
            font-family: var(--font-head);
            font-size: 11px;
            padding: 8px 14px;
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            gap: 6px;
            letter-spacing: 1px;
            text-decoration: none;
        }

        .hud-btn:hover {
            background: var(--cyan-glow);
            color: #000;
            box-shadow: 0 0 20px rgba(0, 243, 255, 0.7);
            transform: translateY(-1px);
        }

        .hud-btn-danger {
            background: linear-gradient(135deg, rgba(255,0,85,0.2), rgba(150,0,50,0.4));
            border: 1px solid var(--red-glow);
        }

        .hud-btn-danger:hover {
            background: var(--red-glow);
            color: #fff;
            box-shadow: 0 0 20px rgba(255, 0, 85, 0.8);
        }

        .hud-btn-google {
            background: linear-gradient(135deg, rgba(234,67,53,0.2), rgba(66,133,244,0.3));
            border: 1px solid #4285f4;
        }

        .hud-btn-google:hover {
            background: #4285f4;
            color: #fff;
            box-shadow: 0 0 20px rgba(66, 133, 244, 0.8);
        }

        /* Hero Banner */
        .hero-banner {
            background: rgba(5, 12, 26, 0.9);
            border: 1px solid var(--border-cyan);
            border-radius: 16px;
            padding: 24px;
            display: grid;
            grid-template-columns: 1fr 1.2fr;
            gap: 24px;
            align-items: center;
            position: relative;
            overflow: hidden;
            box-shadow: 0 0 30px rgba(0, 0, 0, 0.8);
        }

        .hero-banner::after {
            content: '';
            position: absolute;
            bottom: 0; right: 0; left: 0; height: 1px;
            background: linear-gradient(90deg, transparent, var(--red-glow), transparent);
        }

        .hero-text {
            display: flex;
            flex-direction: column;
            gap: 14px;
        }

        .cyber-badge {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: var(--red-dim);
            border: 1px solid var(--red-glow);
            color: var(--red-glow);
            font-family: var(--font-head);
            font-size: 11px;
            letter-spacing: 2px;
            padding: 6px 12px;
            border-radius: 4px;
            width: fit-content;
        }

        .hero-title {
            font-family: var(--font-head);
            font-size: 30px;
            font-weight: 900;
            line-height: 1.2;
            color: #ffffff;
            letter-spacing: 1px;
        }

        .hero-title span {
            color: var(--red-glow);
            text-shadow: 0 0 15px rgba(255, 0, 85, 0.6);
        }

        .hero-desc {
            color: var(--text-muted);
            font-size: 14px;
            line-height: 1.6;
        }

        /* Preset Chips */
        .preset-container {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-top: 6px;
        }

        .preset-chip {
            background: rgba(0, 243, 255, 0.05);
            border: 1px solid rgba(0, 243, 255, 0.2);
            color: var(--text-main);
            font-size: 12px;
            padding: 8px 14px;
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            gap: 6px;
            font-family: var(--font-code);
        }

        .preset-chip:hover {
            border-color: var(--cyan-glow);
            background: rgba(0, 243, 255, 0.15);
            color: var(--cyan-glow);
            transform: translateY(-2px);
        }

        .preset-chip.danger:hover {
            border-color: var(--red-glow);
            background: rgba(255, 0, 85, 0.15);
            color: var(--red-glow);
        }

        /* Hero Graphic Display */
        .hero-graphic {
            position: relative;
            height: 240px;
            background: radial-gradient(ellipse at center, rgba(0,243,255,0.08) 0%, rgba(3,7,18,0.95) 80%);
            border: 1px solid rgba(0, 243, 255, 0.25);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            overflow: hidden;
        }

        .wireframe-mesh-svg {
            position: absolute;
            width: 100%;
            height: 100%;
            opacity: 0.85;
        }

        .warning-overlay {
            position: relative;
            z-index: 2;
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 10px;
        }

        .triangle-icon-wrapper {
            position: relative;
            width: 80px;
            height: 80px;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .triangle-glow-bg {
            position: absolute;
            width: 70px;
            height: 70px;
            border-radius: 50%;
            background: radial-gradient(circle, rgba(255,0,85,0.4) 0%, transparent 70%);
            animation: pulse-glow 2s infinite alternate;
        }

        @keyframes pulse-glow {
            0% { transform: scale(0.9); opacity: 0.5; }
            100% { transform: scale(1.3); opacity: 0.9; }
        }

        .warning-svg {
            width: 70px;
            height: 65px;
            filter: drop-shadow(0 0 10px rgba(255, 0, 85, 0.8));
        }

        .hud-digital-tag {
            font-family: var(--font-head);
            font-size: 11px;
            letter-spacing: 3px;
            color: var(--cyan-glow);
            text-shadow: 0 0 8px var(--cyan-glow);
        }

        /* Navigation Tabs */
        .tabs-nav {
            display: flex;
            gap: 12px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            padding-bottom: 12px;
            flex-wrap: wrap;
        }

        .tab-btn {
            background: rgba(10, 20, 38, 0.6);
            border: 1px solid rgba(255, 255, 255, 0.1);
            color: var(--text-muted);
            font-family: var(--font-head);
            font-size: 13px;
            padding: 12px 22px;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .tab-btn:hover {
            border-color: var(--border-cyan);
            color: var(--cyan-glow);
            background: rgba(0, 243, 255, 0.08);
        }

        .tab-btn.active {
            background: linear-gradient(135deg, rgba(0,243,255,0.2), rgba(0,80,140,0.4));
            border-color: var(--cyan-glow);
            color: #ffffff;
            box-shadow: 0 0 15px rgba(0, 243, 255, 0.25);
        }

        /* Content Sections */
        .tab-content {
            display: none;
            flex-direction: column;
            gap: 20px;
        }

        .tab-content.active {
            display: flex;
        }

        /* Grid Layout for Scanner */
        .scanner-grid {
            display: grid;
            grid-template-columns: 1fr 1.15fr;
            gap: 20px;
        }

        @media (max-width: 1024px) {
            .hero-banner { grid-template-columns: 1fr; }
            .scanner-grid { grid-template-columns: 1fr; }
        }

        .cyber-card {
            background: var(--bg-card);
            border: 1px solid var(--border-cyan);
            border-radius: 14px;
            padding: 24px;
            backdrop-filter: blur(12px);
            box-shadow: 0 0 25px rgba(0, 0, 0, 0.5);
            display: flex;
            flex-direction: column;
            gap: 18px;
            position: relative;
        }

        .cyber-card-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            border-bottom: 1px solid rgba(0, 243, 255, 0.15);
            padding-bottom: 14px;
        }

        .card-title {
            font-family: var(--font-head);
            font-size: 16px;
            color: #ffffff;
            display: flex;
            align-items: center;
            gap: 10px;
            letter-spacing: 1px;
        }

        .card-title i {
            color: var(--cyan-glow);
        }

        /* Form Inputs */
        .form-group {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }

        .form-label {
            font-family: var(--font-code);
            font-size: 12px;
            color: var(--text-cyber);
            text-transform: uppercase;
            letter-spacing: 1px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .form-input, .form-textarea {
            background: rgba(3, 7, 18, 0.8);
            border: 1px solid rgba(0, 243, 255, 0.25);
            border-radius: 8px;
            padding: 12px 14px;
            color: #ffffff;
            font-family: var(--font-code);
            font-size: 13px;
            transition: all 0.2s ease;
            outline: none;
        }

        .form-input:focus, .form-textarea:focus {
            border-color: var(--cyan-glow);
            box-shadow: 0 0 12px rgba(0, 243, 255, 0.3);
            background: rgba(5, 15, 30, 0.95);
        }

        .form-textarea {
            resize: vertical;
            min-height: 120px;
        }

        .scan-submit-btn {
            background: linear-gradient(135deg, #ff0055, #b3003b);
            border: 1px solid #ff0055;
            color: #ffffff;
            font-family: var(--font-head);
            font-size: 15px;
            font-weight: 700;
            padding: 14px 28px;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.25s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 12px;
            letter-spacing: 2px;
            box-shadow: 0 0 20px rgba(255, 0, 85, 0.4);
            margin-top: 10px;
        }

        .scan-submit-btn:hover {
            box-shadow: 0 0 30px rgba(255, 0, 85, 0.8);
            transform: translateY(-2px);
            background: linear-gradient(135deg, #ff1a66, #d90048);
        }

        .scan-submit-btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            transform: none;
        }

        /* Scan Progress Radar */
        .scan-pipeline {
            display: none;
            flex-direction: column;
            gap: 10px;
            margin-top: 10px;
        }

        .scan-pipeline.active {
            display: flex;
        }

        .pipeline-step {
            display: flex;
            align-items: center;
            gap: 14px;
            padding: 10px 14px;
            background: rgba(0, 243, 255, 0.04);
            border: 1px solid rgba(0, 243, 255, 0.15);
            border-radius: 8px;
            font-family: var(--font-code);
            font-size: 12px;
            color: var(--text-muted);
            transition: all 0.3s ease;
        }

        .pipeline-step.completed {
            border-color: var(--green-glow);
            color: var(--text-main);
            background: rgba(0, 255, 136, 0.08);
        }

        .pipeline-step.running {
            border-color: var(--cyan-glow);
            color: var(--cyan-glow);
            background: rgba(0, 243, 255, 0.12);
            box-shadow: 0 0 12px rgba(0, 243, 255, 0.2);
        }

        .pipeline-step i {
            width: 18px;
            text-align: center;
        }

        /* Results Display */
        .verdict-box {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 20px 24px;
            border-radius: 12px;
            background: rgba(0, 0, 0, 0.5);
            border: 2px solid rgba(255, 255, 255, 0.1);
            position: relative;
            flex-wrap: wrap;
            gap: 14px;
        }

        .verdict-box.MALICIOUS, .verdict-box.PHISHING, .verdict-box.CRITICAL {
            border-color: var(--red-glow);
            background: radial-gradient(circle at left, rgba(255,0,85,0.2) 0%, rgba(3,7,18,0.9) 100%);
            box-shadow: 0 0 30px rgba(255, 0, 85, 0.3);
        }

        .verdict-box.SUSPICIOUS, .verdict-box.HIGH {
            border-color: var(--amber-glow);
            background: radial-gradient(circle at left, rgba(255,183,0,0.2) 0%, rgba(3,7,18,0.9) 100%);
            box-shadow: 0 0 30px rgba(255, 183, 0, 0.3);
        }

        .verdict-box.BENIGN, .verdict-box.SAFE, .verdict-box.CLEAN, .verdict-box.LOW {
            border-color: var(--green-glow);
            background: radial-gradient(circle at left, rgba(0,255,136,0.2) 0%, rgba(3,7,18,0.9) 100%);
            box-shadow: 0 0 30px rgba(0, 255, 136, 0.3);
        }

        .verdict-title {
            font-family: var(--font-head);
            font-size: 24px;
            letter-spacing: 2px;
            font-weight: 900;
        }

        .verdict-box.MALICIOUS .verdict-title, .verdict-box.PHISHING .verdict-title, .verdict-box.CRITICAL .verdict-title { color: var(--red-glow); }
        .verdict-box.SUSPICIOUS .verdict-title, .verdict-box.HIGH .verdict-title { color: var(--amber-glow); }
        .verdict-box.BENIGN .verdict-title, .verdict-box.SAFE .verdict-title, .verdict-box.CLEAN .verdict-title, .verdict-box.LOW .verdict-title { color: var(--green-glow); }

        .badges-group {
            display: flex;
            align-items: center;
            gap: 10px;
            flex-wrap: wrap;
        }

        .badge-tag {
            font-family: var(--font-code);
            font-size: 12px;
            padding: 6px 14px;
            border-radius: 20px;
            background: rgba(255, 255, 255, 0.08);
            border: 1px solid rgba(255, 255, 255, 0.2);
            color: #fff;
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .badge-priority {
            font-weight: 700;
            border-color: var(--red-glow);
            background: var(--red-dim);
            color: var(--red-glow);
        }

        /* Risk Metric Strip */
        .risk-metric-card {
            background: rgba(4, 11, 24, 0.85);
            border: 1px solid var(--border-cyan);
            border-radius: 12px;
            padding: 16px 20px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 20px;
        }

        .score-display-wrapper {
            display: flex;
            align-items: baseline;
            gap: 6px;
        }

        .score-val-big {
            font-family: var(--font-head);
            font-size: 36px;
            font-weight: 900;
            color: var(--cyan-glow);
        }

        .score-max {
            font-family: var(--font-code);
            font-size: 14px;
            color: var(--text-muted);
        }

        /* Factor Breakdown Table */
        .factor-grid {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }

        .factor-item {
            background: rgba(0, 0, 0, 0.4);
            border: 1px solid rgba(0, 243, 255, 0.15);
            border-radius: 8px;
            padding: 12px 16px;
            display: flex;
            flex-direction: column;
            gap: 6px;
        }

        .factor-head {
            display: flex;
            align-items: center;
            justify-content: space-between;
            font-family: var(--font-code);
            font-size: 12px;
        }

        .factor-name {
            color: var(--cyan-glow);
            font-weight: 700;
            text-transform: uppercase;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .factor-pts {
            color: var(--red-glow);
            font-weight: 700;
        }

        .factor-reason {
            font-size: 13px;
            color: var(--text-main);
            line-height: 1.4;
        }

        /* MITRE & IoC Badges */
        .chips-cloud {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
        }

        .mitre-chip {
            background: rgba(255, 0, 85, 0.1);
            border: 1px solid var(--red-glow);
            color: #ff99bb;
            font-family: var(--font-code);
            font-size: 12px;
            padding: 6px 12px;
            border-radius: 6px;
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .ioc-chip {
            background: rgba(0, 243, 255, 0.08);
            border: 1px solid rgba(0, 243, 255, 0.3);
            color: var(--cyan-glow);
            font-family: var(--font-code);
            font-size: 12px;
            padding: 6px 12px;
            border-radius: 6px;
            word-break: break-all;
        }

        /* Evidence Cards */
        .evidence-list {
            display: flex;
            flex-direction: column;
            gap: 8px;
            max-height: 280px;
            overflow-y: auto;
            padding-right: 6px;
        }

        .evidence-item {
            background: rgba(0, 0, 0, 0.4);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 8px;
            padding: 10px 14px;
            display: flex;
            flex-direction: column;
            gap: 4px;
        }

        .evidence-head {
            display: flex;
            align-items: center;
            justify-content: space-between;
            font-family: var(--font-code);
            font-size: 11px;
        }

        .evidence-desc {
            font-size: 13px;
            color: var(--text-main);
            line-height: 1.4;
        }

        /* Analyst Notes Box */
        .notes-box {
            background: rgba(3, 7, 18, 0.85);
            border-left: 3px solid var(--cyan-glow);
            padding: 12px 16px;
            border-radius: 0 8px 8px 0;
            font-family: var(--font-code);
            font-size: 12px;
            color: var(--text-muted);
            line-height: 1.6;
            white-space: pre-wrap;
        }

        /* Gmail Cards Grid */
        .gmail-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(480px, 1fr));
            gap: 16px;
        }

        @media (max-width: 768px) {
            .gmail-grid { grid-template-columns: 1fr; }
        }

        .gmail-card {
            background: rgba(4, 11, 24, 0.85);
            border: 1px solid rgba(0, 243, 255, 0.2);
            border-radius: 12px;
            padding: 18px;
            display: flex;
            flex-direction: column;
            gap: 12px;
            transition: all 0.25s ease;
            position: relative;
        }

        .gmail-card:hover {
            border-color: var(--cyan-glow);
            box-shadow: 0 0 20px rgba(0, 243, 255, 0.2);
            transform: translateY(-2px);
            background: rgba(8, 20, 42, 0.95);
        }

        .gmail-card-header {
            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            gap: 12px;
        }

        .gmail-sender {
            font-family: var(--font-code);
            font-size: 13px;
            color: var(--cyan-glow);
            font-weight: 600;
            word-break: break-all;
        }

        .gmail-date {
            font-family: var(--font-code);
            font-size: 11px;
            color: var(--text-muted);
            white-space: nowrap;
        }

        .gmail-subject {
            font-family: var(--font-body);
            font-size: 15px;
            font-weight: 600;
            color: #ffffff;
            line-height: 1.3;
        }

        .gmail-snippet {
            font-size: 13px;
            color: var(--text-muted);
            line-height: 1.5;
            display: -webkit-box;
            -webkit-line-clamp: 2;
            -webkit-box-orient: vertical;
            overflow: hidden;
            background: rgba(0,0,0,0.3);
            padding: 8px 12px;
            border-radius: 6px;
            border-left: 2px solid var(--cyan-glow);
        }

        .gmail-actions {
            display: flex;
            justify-content: flex-end;
            margin-top: 4px;
        }

        /* History Table */
        .cyber-table {
            width: 100%;
            border-collapse: collapse;
            font-family: var(--font-code);
            font-size: 13px;
        }

        .cyber-table th {
            background: rgba(0, 243, 255, 0.08);
            color: var(--cyan-glow);
            text-align: left;
            padding: 14px 16px;
            border-bottom: 1px solid var(--border-cyan);
            font-family: var(--font-head);
            font-size: 11px;
            letter-spacing: 1px;
        }

        .cyber-table td {
            padding: 14px 16px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            color: var(--text-main);
        }

        .cyber-table tr:hover {
            background: rgba(0, 243, 255, 0.04);
        }

        /* Code & JSON Display */
        pre.json-view {
            background: rgba(2, 6, 16, 0.95);
            border: 1px solid var(--border-cyan);
            border-radius: 8px;
            padding: 16px;
            font-family: var(--font-code);
            font-size: 12px;
            color: var(--text-cyber);
            max-height: 380px;
            overflow: auto;
            line-height: 1.5;
        }

        /* Telemetry Cards */
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
        }

        .metric-card {
            background: rgba(6, 15, 30, 0.7);
            border: 1px solid var(--border-cyan);
            border-radius: 12px;
            padding: 18px;
            display: flex;
            align-items: center;
            gap: 16px;
        }

        .metric-icon {
            width: 44px;
            height: 44px;
            border-radius: 10px;
            background: rgba(0, 243, 255, 0.1);
            border: 1px solid var(--cyan-glow);
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--cyan-glow);
            font-size: 18px;
        }

        .metric-val {
            font-family: var(--font-head);
            font-size: 20px;
            color: #fff;
        }

        .metric-lbl {
            font-family: var(--font-code);
            font-size: 11px;
            color: var(--text-muted);
            text-transform: uppercase;
        }

        /* Auth Modal */
        .modal-overlay {
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(0, 0, 0, 0.85);
            backdrop-filter: blur(8px);
            z-index: 99;
            display: none;
            align-items: center;
            justify-content: center;
        }

        .modal-overlay.active {
            display: flex;
        }

        .modal-box {
            width: 440px;
            max-width: 90vw;
            background: rgba(10, 20, 38, 0.95);
            border: 1px solid var(--cyan-glow);
            border-radius: 14px;
            padding: 28px;
            box-shadow: 0 0 40px rgba(0, 243, 255, 0.3);
            display: flex;
            flex-direction: column;
            gap: 20px;
        }
    </style>
</head>
<body>
    <!-- Matrix Rain Canvas -->
    <canvas id="cyber-canvas"></canvas>

    <div class="app-container">
        <!-- HUD Header -->
        <header class="hud-header">
            <div class="brand">
                <div class="brand-icon">
                    <i class="fa-solid fa-shield-halved"></i>
                </div>
                <div class="brand-text">
                    <h1>SCAMSHIELD</h1>
                    <p>Cyber Threat Command Center</p>
                </div>
            </div>
            <div class="hud-status-bar">
                <div id="status-api" class="status-pill">
                    <div id="dot-api" class="status-dot"></div>
                    <span id="txt-api">API: CONNECTED</span>
                </div>
                <div id="status-db" class="status-pill">
                    <div id="dot-db" class="status-dot"></div>
                    <span id="txt-db">DB: VERIFYING</span>
                </div>
                <div id="status-redis" class="status-pill">
                    <div id="dot-redis" class="status-dot"></div>
                    <span id="txt-redis">REDIS: VERIFYING</span>
                </div>
                <div id="status-pgvector" class="status-pill">
                    <div id="dot-pgvector" class="status-dot"></div>
                    <span id="txt-pgvector">PGVECTOR: VERIFYING</span>
                </div>
                <div id="gmail-status-pill" class="status-pill">
                    <div id="gmail-status-dot" class="status-dot disconnected"></div>
                    <span id="gmail-status-text">GMAIL: CHECKING</span>
                </div>
                <a id="btn-connect-gmail" href="/auth/google/login" class="hud-btn hud-btn-google">
                    <i class="fa-brands fa-google"></i> GMAIL AUTH
                </a>
                <button class="hud-btn" onclick="openAuthModal()">
                    <i class="fa-solid fa-key"></i> AUTH KEYS
                </button>
            </div>
        </header>

        <!-- Hero Cyber Security Visual Banner -->
        <div class="hero-banner">
            <div class="hero-text">
                <div class="cyber-badge">
                    <i class="fa-solid fa-triangle-exclamation"></i> ADVANCED EMAIL ANALYSIS AGENT
                </div>
                <h2 class="hero-title">CYBER SECURITY <span>THREAT ANALYSIS</span></h2>
                <p class="hero-desc">
                    Multi-step agentic investigation pipeline powered by neural embeddings, pgvector semantic memory, factor-weighted explainable risk scoring, and real-time security intelligence.
                </p>
                <div class="preset-container">
                    <span style="font-family: var(--font-code); font-size: 11px; color: var(--text-cyber); width: 100%;">LOAD TEST SCENARIOS:</span>
                    <div class="preset-chip danger" onclick="loadPreset('phishing')">
                        <i class="fa-solid fa-bolt"></i> M365 Credential Alert
                    </div>
                    <div class="preset-chip danger" onclick="loadPreset('paypal')">
                        <i class="fa-solid fa-building-columns"></i> PayPal Urgent Restriction
                    </div>
                    <div class="preset-chip danger" onclick="loadPreset('ceo')">
                        <i class="fa-solid fa-user-secret"></i> Urgent Wire Transfer
                    </div>
                    <div class="preset-chip" onclick="loadPreset('clean')">
                        <i class="fa-solid fa-circle-check"></i> Safe Meeting Memo
                    </div>
                </div>
            </div>

            <!-- Wireframe & Warning Graphic Display -->
            <div class="hero-graphic">
                <svg class="wireframe-mesh-svg" viewBox="0 0 400 200">
                    <defs>
                        <linearGradient id="cyber-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                            <stop offset="0%" stop-color="#00f3ff" stop-opacity="0.6"/>
                            <stop offset="100%" stop-color="#ff0055" stop-opacity="0.6"/>
                        </linearGradient>
                    </defs>
                    <g stroke="url(#cyber-grad)" stroke-width="1" fill="none" opacity="0.4">
                        <polygon points="120,180 160,130 200,160 240,130 280,180" />
                        <polygon points="160,130 200,80 240,130" />
                        <polygon points="200,80 170,40 230,40" />
                        <polygon points="170,40 200,20 230,40" />
                        <line x1="80" y1="180" x2="120" y2="180" />
                        <line x1="280" y1="180" x2="320" y2="180" />
                        <line x1="160" y1="130" x2="110" y2="110" />
                        <line x1="240" y1="130" x2="290" y2="110" />
                        <line x1="0" y1="190" x2="400" y2="190" stroke="#00f3ff" stroke-width="1.5" opacity="0.6"/>
                        <line x1="0" y1="195" x2="400" y2="195" stroke="#ff0055" stroke-width="1" opacity="0.4"/>
                    </g>
                    <circle cx="200" cy="80" r="3" fill="#00f3ff"/>
                    <circle cx="160" cy="130" r="3" fill="#ff0055"/>
                    <circle cx="240" cy="130" r="3" fill="#00f3ff"/>
                    <circle cx="170" cy="40" r="3" fill="#00f3ff"/>
                    <circle cx="230" cy="40" r="3" fill="#00f3ff"/>
                </svg>

                <div class="warning-overlay">
                    <div class="triangle-icon-wrapper">
                        <div class="triangle-glow-bg"></div>
                        <svg class="warning-svg" viewBox="0 0 100 90">
                            <polygon points="50,5 95,85 5,85" fill="none" stroke="#ff0055" stroke-width="6" stroke-linejoin="round"/>
                            <polygon points="50,15 85,78 15,78" fill="rgba(255, 0, 85, 0.2)"/>
                            <rect x="46" y="32" width="8" height="24" rx="4" fill="#ff0055"/>
                            <circle cx="50" cy="66" r="4.5" fill="#ff0055"/>
                        </svg>
                    </div>
                    <div class="hud-digital-tag">SOC AGENT ACTIVE</div>
                </div>
            </div>
        </div>

        <!-- Navigation Tabs -->
        <nav class="tabs-nav">
            <button id="nav-btn-scanner" class="tab-btn active" onclick="switchTab('scanner')">
                <i class="fa-solid fa-magnifying-glass"></i> THREAT SCANNER
            </button>
            <button id="nav-btn-gmail" class="tab-btn" onclick="switchTab('gmail')">
                <i class="fa-brands fa-google"></i> LIVE GMAIL INBOX (10)
            </button>
            <button id="nav-btn-history" class="tab-btn" onclick="switchTab('history')">
                <i class="fa-solid fa-clock-rotate-left"></i> INCIDENT HISTORY
            </button>
            <button id="nav-btn-memory" class="tab-btn" onclick="switchTab('memory')">
                <i class="fa-solid fa-brain"></i> VECTOR MEMORY SEARCH
            </button>
            <button id="nav-btn-telemetry" class="tab-btn" onclick="switchTab('telemetry')">
                <i class="fa-solid fa-chart-line"></i> SYSTEM TELEMETRY
            </button>
        </nav>

        <!-- Tab 1: Scanner Studio -->
        <div id="tab-scanner" class="tab-content active">
            <div class="scanner-grid">
                <!-- Investigation Input Card -->
                <div class="cyber-card">
                    <div class="cyber-card-header">
                        <div class="card-title">
                            <i class="fa-solid fa-terminal"></i> INVESTIGATION DISPATCH
                        </div>
                        <span style="font-family: var(--font-code); font-size: 11px; color: var(--text-cyber);">POST /api/v1/investigate</span>
                    </div>

                    <form id="investigate-form" onsubmit="handleInvestigate(event)" style="display: flex; flex-direction: column; gap: 14px;">
                        <div class="form-group">
                            <label class="form-label">Sender Email Address</label>
                            <input type="text" id="input-sender" class="form-input" placeholder="e.g. security@microsoft-support.example" required>
                        </div>

                        <div class="form-group">
                            <label class="form-label">Email Subject Line</label>
                            <input type="text" id="input-subject" class="form-input" placeholder="e.g. Microsoft 365 account security alert" required>
                        </div>

                        <div class="form-group">
                            <label class="form-label">Email Body Payload</label>
                            <textarea id="input-body" class="form-textarea" placeholder="Paste suspicious email text content or header raw information..." required></textarea>
                        </div>

                        <button type="submit" id="btn-scan" class="scan-submit-btn">
                            <i class="fa-solid fa-crosshairs"></i> INITIATE THREAT SCAN
                        </button>
                    </form>

                    <!-- Scan Radar Steps -->
                    <div id="scan-pipeline" class="scan-pipeline">
                        <div id="step-1" class="pipeline-step"><i class="fa-solid fa-file-code"></i> <span>1. Parsing Header, Structure & Security Tools</span></div>
                        <div id="step-2" class="pipeline-step"><i class="fa-solid fa-shield-virus"></i> <span>2. Sender Infrastructure & Impersonation Analysis</span></div>
                        <div id="step-3" class="pipeline-step"><i class="fa-solid fa-link"></i> <span>3. URL Typosquatting & Link Inspection</span></div>
                        <div id="step-4" class="pipeline-step"><i class="fa-solid fa-user-secret"></i> <span>4. NLP Social Engineering & Urgency Analysis</span></div>
                        <div id="step-5" class="pipeline-step"><i class="fa-solid fa-database"></i> <span>5. pgvector Semantic Memory & Historical RAG</span></div>
                        <div id="step-6" class="pipeline-step"><i class="fa-solid fa-brain"></i> <span>6. LLM Multi-Step Reasoning & Factor Risk Scoring</span></div>
                    </div>
                </div>

                <!-- Analysis Verdict & Report Card -->
                <div class="cyber-card">
                    <div class="cyber-card-header">
                        <div class="card-title">
                            <i class="fa-solid fa-microchip"></i> THREAT ANALYSIS REPORT
                        </div>
                        <span id="scan-time-tag" style="font-family: var(--font-code); font-size: 11px; color: var(--text-muted);">AWAITING SCAN</span>
                    </div>

                    <div id="results-placeholder" style="display: flex; flex-direction: column; align-items: center; justify-content: center; height: 380px; gap: 14px; color: var(--text-muted);">
                        <i class="fa-solid fa-radar" style="font-size: 48px; color: var(--cyan-glow); opacity: 0.5;"></i>
                        <p style="font-family: var(--font-code); font-size: 13px;">Submit an email investigation or pick a scenario above to start scanning.</p>
                    </div>

                    <div id="results-container" style="display: none; flex-direction: column; gap: 16px;">
                        <!-- Verdict Header -->
                        <div id="verdict-banner" class="verdict-box BENIGN">
                            <div>
                                <div id="verdict-text" class="verdict-title">SAFE</div>
                                <div id="threat-class-text" style="font-family: var(--font-code); font-size: 12px; color: var(--text-cyber); margin-top: 4px;"></div>
                            </div>
                            <div class="badges-group">
                                <div id="confidence-tag" class="badge-tag"><i class="fa-solid fa-bullseye"></i> Confidence: 98%</div>
                                <div id="priority-tag" class="badge-tag badge-priority"><i class="fa-solid fa-flag"></i> P4</div>
                            </div>
                        </div>

                        <!-- Risk Score Gauge & Metric Card -->
                        <div class="risk-metric-card">
                            <div>
                                <div style="font-family: var(--font-code); font-size: 11px; color: var(--text-muted); text-transform: uppercase;">FACTOR-WEIGHTED RISK SCORE</div>
                                <div class="score-display-wrapper">
                                    <span id="risk-score-num" class="score-val-big">0.0</span>
                                    <span class="score-max">/ 100.0</span>
                                </div>
                            </div>
                            <div id="risk-tier-badge" class="badge-tag" style="font-size: 13px; font-weight: 700;">LOW RISK</div>
                        </div>

                        <!-- Score Breakdown -->
                        <div class="form-group">
                            <label class="form-label">
                                <span><i class="fa-solid fa-scale-balanced"></i> RISK SCORE BREAKDOWN</span>
                                <span id="factor-count-tag" style="color: var(--text-muted); font-size: 11px;">0 FACTORS</span>
                            </label>
                            <div id="score-breakdown-list" class="factor-grid">
                                <!-- Dynamic Breakdown items -->
                            </div>
                        </div>

                        <!-- MITRE ATT&CK & Threat Indicators -->
                        <div class="form-group">
                            <label class="form-label">
                                <span><i class="fa-solid fa-sitemap"></i> MITRE ATT&CK TACTICAL MAPPINGS</span>
                            </label>
                            <div id="mitre-list" class="chips-cloud">
                                <!-- Dynamic MITRE chips -->
                            </div>
                        </div>

                        <!-- Indicators of Compromise (IoCs) -->
                        <div class="form-group">
                            <label class="form-label">
                                <span><i class="fa-solid fa-fingerprint"></i> EXTRACTED INDICATORS OF COMPROMISE (IoCs)</span>
                            </label>
                            <div id="iocs-list" class="chips-cloud">
                                <!-- Dynamic IoC chips -->
                            </div>
                        </div>

                        <!-- Analyst Notes & Reasoning -->
                        <div class="form-group">
                            <label class="form-label">
                                <span><i class="fa-solid fa-user-shield"></i> ANALYST NOTES & REASONING SUMMARY</span>
                            </label>
                            <div id="analyst-notes-content" class="notes-box"></div>
                        </div>

                        <!-- Evidence Collection Explorer -->
                        <div class="form-group">
                            <label class="form-label">
                                <span><i class="fa-solid fa-list-check"></i> SECURITY EVIDENCE COLLECTION</span>
                                <span id="evidence-count-tag" style="color: var(--text-muted); font-size: 11px;">0 ITEMS</span>
                            </label>
                            <div id="evidence-list" class="evidence-list">
                                <!-- Dynamic Evidence items -->
                            </div>
                        </div>

                        <!-- Raw JSON Toggle -->
                        <button class="hud-btn" style="width: fit-content;" onclick="toggleJsonView()">
                            <i class="fa-solid fa-code"></i> TOGGLE RAW JSON RESPONSE
                        </button>
                        <pre id="json-raw-view" class="json-view" style="display: none;"></pre>
                    </div>
                </div>
            </div>
        </div>

        <!-- Tab 2: Live Gmail Inbox (Last 10) -->
        <div id="tab-gmail" class="tab-content">
            <div class="cyber-card">
                <div class="cyber-card-header">
                    <div class="card-title">
                        <i class="fa-brands fa-google"></i> LIVE GMAIL INBOX &mdash; LAST 10 EMAILS
                    </div>
                    <div style="display: flex; gap: 10px;">
                        <a href="/auth/google/login" class="hud-btn hud-btn-google">
                            <i class="fa-solid fa-arrows-rotate"></i> RECONNECT GMAIL
                        </a>
                        <button class="hud-btn" onclick="fetchGmailLast10()">
                            <i class="fa-solid fa-rotate"></i> REFRESH EMAILS
                        </button>
                    </div>
                </div>

                <div id="gmail-inbox-container">
                    <div id="gmail-loading" style="display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 60px 20px; gap: 16px; color: var(--text-muted);">
                        <i class="fa-solid fa-spinner fa-spin" style="font-size: 36px; color: var(--cyan-glow);"></i>
                        <p style="font-family: var(--font-code); font-size: 13px;">Checking Gmail OAuth connection & fetching latest 10 messages...</p>
                    </div>

                    <div id="gmail-not-connected" style="display: none; flex-direction: column; align-items: center; justify-content: center; padding: 60px 20px; gap: 18px; text-align: center;">
                        <i class="fa-brands fa-google" style="font-size: 54px; color: #4285f4;"></i>
                        <h3 style="font-family: var(--font-head); font-size: 20px; color: #fff;">GMAIL ACCOUNT NOT CONNECTED</h3>
                        <p style="color: var(--text-muted); max-width: 500px; font-size: 14px; line-height: 1.6;">
                            Connect your Google account using <code>credentials.json</code> to fetch and scan your 10 most recent inbox emails for phishing, malicious links, and scam vectors.
                        </p>
                        <a href="/auth/google/login" class="hud-btn hud-btn-google" style="font-size: 14px; padding: 14px 28px; margin-top: 10px;">
                            <i class="fa-brands fa-google"></i> AUTHORIZE & CONNECT GMAIL INBOX
                        </a>
                    </div>

                    <div id="gmail-messages-list" class="gmail-grid" style="display: none;">
                        <!-- Dynamic 10 email cards rendered here -->
                    </div>
                </div>
            </div>
        </div>

        <!-- Tab 3: Incident History -->
        <div id="tab-history" class="tab-content">
            <div class="cyber-card">
                <div class="cyber-card-header">
                    <div class="card-title">
                        <i class="fa-solid fa-clock-rotate-left"></i> TENANT INCIDENT LOGS
                    </div>
                    <button class="hud-btn" onclick="fetchHistory()">
                        <i class="fa-solid fa-rotate-right"></i> REFRESH
                    </button>
                </div>
                <div style="overflow-x: auto;">
                    <table class="cyber-table">
                        <thead>
                            <tr>
                                <th>INVESTIGATION ID</th>
                                <th>SENDER</th>
                                <th>SUBJECT</th>
                                <th>VERDICT</th>
                                <th>RISK LEVEL</th>
                                <th>DURATION</th>
                                <th>ACTIONS</th>
                            </tr>
                        </thead>
                        <tbody id="history-tbody">
                            <tr>
                                <td colspan="7" style="text-align: center; color: var(--text-muted);">Loading investigation history...</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- Tab 4: Vector Memory Search -->
        <div id="tab-memory" class="tab-content">
            <div class="cyber-card">
                <div class="cyber-card-header">
                    <div class="card-title">
                        <i class="fa-solid fa-brain"></i> HYBRID THREAT MEMORY SEARCH
                    </div>
                    <span style="font-family: var(--font-code); font-size: 11px; color: var(--text-cyber);">GET /api/v1/memory/search?q={query}</span>
                </div>
                <div style="display: flex; gap: 12px;">
                    <input type="text" id="memory-search-input" class="form-input" style="flex: 1;" placeholder="Search threat vectors, e.g. 'paypal phishing' or 'credential harvest'..." onkeydown="if(event.key==='Enter') searchMemory()">
                    <button class="hud-btn" onclick="searchMemory()">
                        <i class="fa-solid fa-magnifying-glass"></i> SEARCH
                    </button>
                </div>
                <div id="memory-results" style="display: flex; flex-direction: column; gap: 12px; margin-top: 10px;">
                    <!-- Dynamic Search Results -->
                </div>
            </div>
        </div>

        <!-- Tab 5: System Telemetry & Health -->
        <div id="tab-telemetry" class="tab-content">
            <div class="metrics-grid">
                <div class="metric-card">
                    <div class="metric-icon"><i class="fa-solid fa-heart-pulse"></i></div>
                    <div>
                        <div id="metric-health" class="metric-val">HEALTHY</div>
                        <div class="metric-lbl">API HEALTH</div>
                    </div>
                </div>
                <div class="metric-card">
                    <div class="metric-icon"><i class="fa-solid fa-database"></i></div>
                    <div>
                        <div id="metric-db" class="metric-val">CONNECTED</div>
                        <div class="metric-lbl">POSTGRESQL DB</div>
                    </div>
                </div>
                <div class="metric-card">
                    <div class="metric-icon"><i class="fa-solid fa-bolt"></i></div>
                    <div>
                        <div id="metric-redis" class="metric-val">CONNECTED</div>
                        <div class="metric-lbl">REDIS CACHE & LOCK</div>
                    </div>
                </div>
                <div class="metric-card">
                    <div class="metric-icon"><i class="fa-solid fa-vector-square"></i></div>
                    <div>
                        <div id="metric-pgvector" class="metric-val">CONNECTED</div>
                        <div class="metric-lbl">PGVECTOR MEMORY</div>
                    </div>
                </div>
            </div>

            <div class="cyber-card">
                <div class="cyber-card-header">
                    <div class="card-title"><i class="fa-solid fa-cubes"></i> ENDPOINT DIRECTORY</div>
                </div>
                <div style="display: flex; gap: 14px; flex-wrap: wrap;">
                    <a href="/docs" target="_blank" class="hud-btn"><i class="fa-solid fa-book"></i> OPEN SWAGGER UI (/docs)</a>
                    <a href="/redoc" target="_blank" class="hud-btn"><i class="fa-solid fa-file-lines"></i> OPEN REDOC (/redoc)</a>
                    <a href="/health" target="_blank" class="hud-btn"><i class="fa-solid fa-code"></i> RAW /health</a>
                    <a href="/ready" target="_blank" class="hud-btn"><i class="fa-solid fa-server"></i> RAW /ready</a>
                    <a href="/metrics" target="_blank" class="hud-btn"><i class="fa-solid fa-chart-simple"></i> RAW /metrics</a>
                </div>
            </div>
        </div>
    </div>

    <!-- Auth Modal -->
    <div id="auth-modal" class="modal-overlay">
        <div class="modal-box">
            <div style="display: flex; align-items: center; justify-content: space-between;">
                <div style="font-family: var(--font-head); font-size: 16px; color: #fff;">AUTHENTICATION KEYS</div>
                <button class="hud-btn" style="padding: 4px 8px;" onclick="closeAuthModal()"><i class="fa-solid fa-xmark"></i></button>
            </div>
            <div class="form-group">
                <label class="form-label">JWT Bearer Token</label>
                <textarea id="modal-jwt-token" class="form-textarea" style="min-height: 80px;" placeholder="Paste custom JWT token or leave auto-provisioned demo token"></textarea>
            </div>
            <div style="display: flex; gap: 10px; justify-content: flex-end;">
                <button class="hud-btn hud-btn-danger" onclick="requestNewDemoToken()">GENERATE DEMO TOKEN</button>
                <button class="hud-btn" onclick="saveAuthToken()">SAVE & CLOSE</button>
            </div>
        </div>
    </div>

    <!-- Incident Detail Modal -->
    <div id="incident-modal" class="modal-overlay">
        <div class="modal-box" style="max-width: 650px;">
            <div style="display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid var(--border-cyber); padding-bottom: 12px; margin-bottom: 16px;">
                <div style="font-family: var(--font-head); font-size: 16px; color: #fff; display: flex; align-items: center; gap: 8px;">
                    <i class="fa-solid fa-shield-halved" style="color: var(--cyan-glow);"></i> INCIDENT INVESTIGATION RECORD
                </div>
                <button class="hud-btn" style="padding: 4px 8px;" onclick="closeIncidentModal()"><i class="fa-solid fa-xmark"></i></button>
            </div>

            <div id="incident-modal-loading" style="display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 40px; gap: 12px;">
                <i class="fa-solid fa-spinner fa-spin" style="font-size: 28px; color: var(--cyan-glow);"></i>
                <div style="font-family: var(--font-code); font-size: 12px; color: var(--text-muted);">Fetching incident record from database...</div>
            </div>

            <div id="incident-modal-content" style="display: none; flex-direction: column; gap: 14px;">
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
                    <div style="background: rgba(3,7,18,0.6); border: 1px solid var(--border-cyber); padding: 10px; border-radius: 6px;">
                        <div style="font-size: 11px; color: var(--text-muted); font-family: var(--font-code);">INVESTIGATION ID</div>
                        <div id="inc-modal-id" style="font-family: var(--font-code); font-size: 13px; color: var(--cyan-glow); font-weight: 700; margin-top: 4px;"></div>
                    </div>
                    <div style="background: rgba(3,7,18,0.6); border: 1px solid var(--border-cyber); padding: 10px; border-radius: 6px;">
                        <div style="font-size: 11px; color: var(--text-muted); font-family: var(--font-code);">ORGANIZATION TENANT</div>
                        <div id="inc-modal-org" style="font-family: var(--font-code); font-size: 13px; color: #fff; margin-top: 4px;"></div>
                    </div>
                </div>

                <div style="background: rgba(3,7,18,0.6); border: 1px solid var(--border-cyber); padding: 10px; border-radius: 6px;">
                    <div style="font-size: 11px; color: var(--text-muted); font-family: var(--font-code);">SENDER ADDRESS</div>
                    <div id="inc-modal-sender" style="font-family: var(--font-code); font-size: 13px; color: #fff; margin-top: 4px;"></div>
                </div>

                <div style="background: rgba(3,7,18,0.6); border: 1px solid var(--border-cyber); padding: 10px; border-radius: 6px;">
                    <div style="font-size: 11px; color: var(--text-muted); font-family: var(--font-code);">SUBJECT LINE</div>
                    <div id="inc-modal-subject" style="font-size: 13px; color: #fff; margin-top: 4px;"></div>
                </div>

                <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 12px;">
                    <div style="background: rgba(3,7,18,0.6); border: 1px solid var(--border-cyber); padding: 10px; border-radius: 6px; text-align: center;">
                        <div style="font-size: 11px; color: var(--text-muted); font-family: var(--font-code);">VERDICT</div>
                        <div id="inc-modal-verdict" style="font-family: var(--font-head); font-size: 13px; font-weight: 700; margin-top: 4px;"></div>
                    </div>
                    <div style="background: rgba(3,7,18,0.6); border: 1px solid var(--border-cyber); padding: 10px; border-radius: 6px; text-align: center;">
                        <div style="font-size: 11px; color: var(--text-muted); font-family: var(--font-code);">RISK LEVEL</div>
                        <div id="inc-modal-risk" style="font-family: var(--font-head); font-size: 13px; font-weight: 700; margin-top: 4px;"></div>
                    </div>
                    <div style="background: rgba(3,7,18,0.6); border: 1px solid var(--border-cyber); padding: 10px; border-radius: 6px; text-align: center;">
                        <div style="font-size: 11px; color: var(--text-muted); font-family: var(--font-code);">CONFIDENCE</div>
                        <div id="inc-modal-conf" style="font-family: var(--font-head); font-size: 13px; color: var(--cyan-glow); font-weight: 700; margin-top: 4px;"></div>
                    </div>
                </div>

                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
                    <div style="background: rgba(3,7,18,0.6); border: 1px solid var(--border-cyber); padding: 10px; border-radius: 6px;">
                        <div style="font-size: 11px; color: var(--text-muted); font-family: var(--font-code);">DURATION</div>
                        <div id="inc-modal-duration" style="font-family: var(--font-code); font-size: 12px; color: #fff; margin-top: 4px;"></div>
                    </div>
                    <div style="background: rgba(3,7,18,0.6); border: 1px solid var(--border-cyber); padding: 10px; border-radius: 6px;">
                        <div style="font-size: 11px; color: var(--text-muted); font-family: var(--font-code);">RECORDED TIMESTAMP</div>
                        <div id="inc-modal-time" style="font-family: var(--font-code); font-size: 12px; color: #fff; margin-top: 4px;"></div>
                    </div>
                </div>

                <div style="display: flex; gap: 10px; justify-content: flex-end; margin-top: 10px;">
                    <button id="inc-modal-reanalyze-btn" class="hud-btn hud-btn-danger" onclick="reanalyzeFromModal()">
                        <i class="fa-solid fa-bolt"></i> LOAD INTO SCANNER
                    </button>
                    <button class="hud-btn" onclick="closeIncidentModal()">CLOSE</button>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Realistic Test Scenarios
        const PRESETS = {
            phishing: {
                sender: "admin@microsoft-secure-login.com",
                subject: "Microsoft 365 Security Alert",
                body: "Hello,\\n\\nYour Microsoft 365 account requires immediate security verification.\\n\\nWe noticed a recent sign-in attempt from an unfamiliar location.\\n\\nPlease verify your account here:\\nhttps://micros0ft-secure-login.com/verify\\n\\nFailure to verify your account within 12 hours may result in temporary account suspension.\\n\\nMicrosoft 365 Security Team"
            },
            paypal: {
                sender: "security@paypa1-support.com",
                subject: "URGENT: Your PayPal account will be suspended",
                body: "Dear Customer,\\n\\nYour PayPal account has been temporarily restricted.\\n\\nWe detected unusual activity on your account. You must verify your identity within 24 hours or your account will be permanently suspended.\\n\\nClick here immediately to verify your account:\\nhttp://paypa1-support.com/verify\\n\\nPlease provide your username, password, and card information to complete verification.\\n\\nPayPal Security Team"
            },
            ceo: {
                sender: "ceo@company-corp-executive.com",
                subject: "URGENT: Confidential Wire Transfer Request",
                body: "Hi Team,\\n\\nI am currently in an urgent board meeting and unable to take phone calls. We are finalizing an acquisition today and need an immediate wire transfer of $48,500 to our external counsel's escrow account.\\n\\nPlease process this wire transfer immediately to Account #984128501 (Routing: 121000358). Keep this strictly confidential until the official press release.\\n\\nThanks,\\nExecutive Management"
            },
            clean: {
                sender: "alice@example.com",
                subject: "Team sync meeting reminder",
                body: "Hi team,\\n\\nReminder for our project sync tomorrow at 10am. We will review our current progress and discuss roadmap goals for next sprint.\\n\\nThanks,\\nAlice"
            }
        };

        let activeAuthToken = localStorage.getItem("scamshield_token") || "";
        let fetchedGmailMessages = [];

        // Matrix Rain Canvas
        const canvas = document.getElementById('cyber-canvas');
        const ctx = canvas.getContext('2d');

        function resizeCanvas() {
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;
        }
        window.addEventListener('resize', resizeCanvas);
        resizeCanvas();

        const chars = '01ABCDEFGHIJKLMNOPQRSTUVWXYZ@#$%&*';
        const fontSize = 12;
        let columns = Math.floor(canvas.width / fontSize);
        let drops = Array(columns).fill(1);

        function drawMatrixRain() {
            ctx.fillStyle = 'rgba(3, 7, 18, 0.15)';
            ctx.fillRect(0, 0, canvas.width, canvas.height);

            ctx.fillStyle = '#00f3ff';
            ctx.font = fontSize + 'px "JetBrains Mono"';

            for (let i = 0; i < drops.length; i++) {
                const text = chars.charAt(Math.floor(Math.random() * chars.length));
                if (Math.random() > 0.96) {
                    ctx.fillStyle = '#ff0055';
                } else {
                    ctx.fillStyle = '#00f3ff';
                }
                ctx.fillText(text, i * fontSize, drops[i] * fontSize);

                if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
                    drops[i] = 0;
                }
                drops[i]++;
            }
        }
        setInterval(drawMatrixRain, 40);

        // Auto-provision Demo JWT
        async function ensureAuthToken() {
            if (!activeAuthToken) {
                await requestNewDemoToken();
            }
        }

        async function requestNewDemoToken() {
            try {
                const res = await fetch('/api/v1/auth/demo-token', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' }
                });

                if (res.ok) {
                    const data = await res.json();
                    activeAuthToken = data.access_token;
                    localStorage.setItem('scamshield_token', activeAuthToken);
                    document.getElementById('modal-jwt-token').value = activeAuthToken;
                }
            } catch (err) {
                console.warn("Auth token initialization error:", err);
            }
        }

        function loadPreset(key) {
            const data = PRESETS[key];
            if (!data) return;
            document.getElementById('input-sender').value = data.sender;
            document.getElementById('input-subject').value = data.subject;
            document.getElementById('input-body').value = data.body;
        }

        function switchTab(tabId) {
            document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

            const navBtn = document.getElementById('nav-btn-' + tabId);
            if (navBtn) navBtn.classList.add('active');

            const contentEl = document.getElementById('tab-' + tabId);
            if (contentEl) contentEl.classList.add('active');

            if (tabId === 'gmail') fetchGmailLast10();
            if (tabId === 'history') fetchHistory();
            if (tabId === 'telemetry') fetchTelemetry();
        }

        function openAuthModal() {
            document.getElementById('modal-jwt-token').value = activeAuthToken;
            document.getElementById('auth-modal').classList.add('active');
        }

        function closeAuthModal() {
            document.getElementById('auth-modal').classList.remove('active');
        }

        function saveAuthToken() {
            activeAuthToken = document.getElementById('modal-jwt-token').value.trim();
            localStorage.setItem('scamshield_token', activeAuthToken);
            closeAuthModal();
        }

        // Live Health & Readiness Probes
        async function checkSystemHealth() {
            try {
                const resReady = await fetch('/ready');
                if (resReady.ok) {
                    const data = await resReady.json();
                    const checks = data.checks || {};

                    // DB
                    const isDbOk = checks.database === 'connected';
                    document.getElementById('dot-db').className = isDbOk ? 'status-dot' : 'status-dot disconnected';
                    document.getElementById('txt-db').innerText = isDbOk ? 'DB: CONNECTED' : 'DB: DEGRADED';
                    document.getElementById('metric-db').innerText = isDbOk ? 'CONNECTED' : 'DEGRADED';

                    // Redis
                    const isRedisOk = checks.redis === 'connected';
                    document.getElementById('dot-redis').className = isRedisOk ? 'status-dot' : (checks.redis === 'degraded_in_memory' ? 'status-dot degraded' : 'status-dot disconnected');
                    document.getElementById('txt-redis').innerText = isRedisOk ? 'REDIS: CONNECTED' : (checks.redis === 'degraded_in_memory' ? 'REDIS: IN-MEMORY' : 'REDIS: DEGRADED');
                    document.getElementById('metric-redis').innerText = isRedisOk ? 'CONNECTED' : 'IN-MEMORY';

                    // pgvector
                    const isPgvOk = checks.pgvector === 'connected';
                    document.getElementById('dot-pgvector').className = isPgvOk ? 'status-dot' : 'status-dot disconnected';
                    document.getElementById('txt-pgvector').innerText = isPgvOk ? 'PGVECTOR: CONNECTED' : 'PGVECTOR: DEGRADED';
                    document.getElementById('metric-pgvector').innerText = isPgvOk ? 'CONNECTED' : 'DEGRADED';
                }

                const resHealth = await fetch('/health');
                if (resHealth.ok) {
                    const dataHealth = await resHealth.json();
                    const isHealthy = dataHealth.status === 'healthy';
                    document.getElementById('dot-api').className = isHealthy ? 'status-dot' : 'status-dot disconnected';
                    document.getElementById('txt-api').innerText = isHealthy ? 'API: HEALTHY' : 'API: UNHEALTHY';
                    document.getElementById('metric-health').innerText = dataHealth.status.toUpperCase();
                }
            } catch (err) {
                console.warn("System readiness probe error:", err);
                document.getElementById('dot-api').className = 'status-dot disconnected';
                document.getElementById('txt-api').innerText = 'API: OFFLINE';
            }
        }

        // Check Gmail Status
        async function checkGmailStatus() {
            try {
                const res = await fetch('/api/v1/gmail/status');
                if (res.ok) {
                    const data = await res.json();
                    const dot = document.getElementById('gmail-status-dot');
                    const txt = document.getElementById('gmail-status-text');

                    if (data.connected) {
                        dot.className = 'status-dot';
                        txt.innerText = 'GMAIL: CONNECTED';
                    } else {
                        dot.className = 'status-dot disconnected';
                        txt.innerText = 'GMAIL: DISCONNECTED';
                    }
                }
            } catch (err) {
                console.warn("Gmail status check failed:", err);
            }
        }

        // Fetch Last 10 Gmail Emails
        async function fetchGmailLast10() {
            const loading = document.getElementById('gmail-loading');
            const notConnected = document.getElementById('gmail-not-connected');
            const msgList = document.getElementById('gmail-messages-list');

            loading.style.display = 'flex';
            notConnected.style.display = 'none';
            msgList.style.display = 'none';

            try {
                const res = await fetch('/api/v1/gmail/fetch-last-10');
                if (!res.ok) {
                    loading.style.display = 'none';
                    notConnected.style.display = 'flex';
                    return;
                }

                const data = await res.json();
                const messages = Array.isArray(data) ? data : (data.messages || []);
                if (messages.length === 0) {
                    loading.style.display = 'none';
                    notConnected.style.display = 'flex';
                    return;
                }

                fetchedGmailMessages = messages;
                loading.style.display = 'none';
                msgList.style.display = 'grid';

                msgList.innerHTML = messages.map((msg, index) => `
                    <div class="gmail-card">
                        <div class="gmail-card-header">
                            <span class="gmail-sender"><i class="fa-solid fa-user-ninja"></i> ${escapeHtml(msg.sender)}</span>
                            <span class="gmail-date">${escapeHtml(msg.date || '')}</span>
                        </div>
                        <div class="gmail-subject">${escapeHtml(msg.subject)}</div>
                        <div class="gmail-snippet">${escapeHtml(msg.snippet || (msg.body ? msg.body.substring(0, 140) : ''))}</div>
                        <div class="gmail-actions">
                            <button class="hud-btn hud-btn-danger" style="font-size: 11px; padding: 8px 14px;" onclick="analyzeGmailMessage(${index})">
                                <i class="fa-solid fa-bolt"></i> ANALYZE THREAT WITH AI
                            </button>
                        </div>
                    </div>
                `).join('');

            } catch (err) {
                loading.style.display = 'none';
                notConnected.style.display = 'flex';
            }
        }

        function analyzeGmailMessage(index) {
            const msg = fetchedGmailMessages[index];
            if (!msg) return;

            document.getElementById('input-sender').value = msg.sender;
            document.getElementById('input-subject').value = msg.subject;
            document.getElementById('input-body').value = msg.body || msg.snippet;

            switchTab('scanner');
            document.getElementById('investigate-form').requestSubmit();
        }

        function escapeHtml(str) {
            if (!str) return '';
            return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
        }

        // Handle Investigation Submission
        async function handleInvestigate(e) {
            e.preventDefault();
            await ensureAuthToken();

            const sender = document.getElementById('input-sender').value.trim();
            const subject = document.getElementById('input-subject').value.trim();
            const body = document.getElementById('input-body').value.trim();

            const submitBtn = document.getElementById('btn-scan');
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> INVESTIGATING...';

            const pipeline = document.getElementById('scan-pipeline');
            pipeline.classList.add('active');

            // Reset step UI
            for (let i = 1; i <= 6; i++) {
                const step = document.getElementById(`step-${i}`);
                step.className = 'pipeline-step';
            }

            let currentStep = 1;
            const stepInterval = setInterval(() => {
                if (currentStep > 1) {
                    document.getElementById(`step-${currentStep-1}`).className = 'pipeline-step completed';
                }
                if (currentStep <= 6) {
                    document.getElementById(`step-${currentStep}`).className = 'pipeline-step running';
                    currentStep++;
                } else {
                    clearInterval(stepInterval);
                }
            }, 350);

            const startTime = Date.now();

            try {
                let res = await fetch('/api/v1/investigate', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + activeAuthToken
                    },
                    body: JSON.stringify({ sender, subject, body })
                });

                if (res.status === 401) {
                    await requestNewDemoToken();
                    res = await fetch('/api/v1/investigate', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': 'Bearer ' + activeAuthToken
                        },
                        body: JSON.stringify({ sender, subject, body })
                    });
                }

                clearInterval(stepInterval);

                for (let i = 1; i <= 6; i++) {
                    document.getElementById(`step-${i}`).className = 'pipeline-step completed';
                }

                if (!res.ok) {
                    const err = await res.json();
                    alert("Investigation Pipeline Error (" + res.status + "): " + (err.detail || (err.error ? err.error.message : JSON.stringify(err))));
                    return;
                }

                const data = await res.json();
                renderResults(data, Date.now() - startTime);

            } catch (err) {
                console.error("Investigation error:", err);
                alert("Investigation failed: " + err.message);
            } finally {
                submitBtn.disabled = false;
                submitBtn.innerHTML = '<i class="fa-solid fa-crosshairs"></i> INITIATE THREAT SCAN';
            }
        }

        // Render Real v1.0-hardening5 Investigation Output
        function renderResults(data, clientLatencyMs) {
            document.getElementById('results-placeholder').style.display = 'none';
            const container = document.getElementById('results-container');
            container.style.display = 'flex';

            const report = data.report || {};
            const execTime = data.execution_time_ms || (report.execution_statistics ? report.execution_statistics.total_investigation_time_ms : clientLatencyMs);
            document.getElementById('scan-time-tag').innerText = `EXECUTION TIME: ${execTime} MS`;

            // Verdict & Risk Banner
            const verdictBanner = document.getElementById('verdict-banner');
            const verdictText = document.getElementById('verdict-text');
            const threatClassText = document.getElementById('threat-class-text');
            const confidenceTag = document.getElementById('confidence-tag');
            const priorityTag = document.getElementById('priority-tag');

            const rawVerdict = data.verdict || report.classification || "UNKNOWN";
            const riskLevel = (data.risk_level || "MEDIUM").toUpperCase();
            const confidence = typeof data.confidence === 'number' ? (data.confidence * 100).toFixed(1) : '90.0';
            const priority = report.recommended_priority || (riskLevel === 'CRITICAL' ? 'P1' : (riskLevel === 'HIGH' ? 'P2' : (riskLevel === 'MEDIUM' ? 'P3' : 'P4')));

            verdictText.innerText = rawVerdict.toUpperCase();
            verdictBanner.className = `verdict-box ${riskLevel}`;

            const threatClasses = report.threat_classification || [];
            threatClassText.innerText = threatClasses.length > 0 ? threatClasses.join(' • ') : (report.incident_category ? report.incident_category.toUpperCase() : '');

            confidenceTag.innerHTML = `<i class="fa-solid fa-bullseye"></i> Confidence: ${confidence}% | ${riskLevel} RISK`;
            priorityTag.innerHTML = `<i class="fa-solid fa-flag"></i> ${priority}`;

            // Risk Score Gauge
            const riskScore = typeof report.risk_score === 'number' ? report.risk_score : (typeof data.risk_score === 'number' ? data.risk_score : 0.0);
            const scoreNumEl = document.getElementById('risk-score-num');
            scoreNumEl.innerText = riskScore.toFixed(1);

            const tierBadge = document.getElementById('risk-tier-badge');
            tierBadge.innerText = `${riskLevel} RISK LEVEL`;
            if (riskLevel === 'CRITICAL' || riskScore >= 50) {
                scoreNumEl.style.color = 'var(--red-glow)';
                tierBadge.style.color = 'var(--red-glow)';
                tierBadge.style.borderColor = 'var(--red-glow)';
                tierBadge.style.background = 'var(--red-dim)';
            } else if (riskLevel === 'HIGH' || riskScore >= 25) {
                scoreNumEl.style.color = 'var(--amber-glow)';
                tierBadge.style.color = 'var(--amber-glow)';
                tierBadge.style.borderColor = 'var(--amber-glow)';
                tierBadge.style.background = 'var(--amber-dim)';
            } else {
                scoreNumEl.style.color = 'var(--green-glow)';
                tierBadge.style.color = 'var(--green-glow)';
                tierBadge.style.borderColor = 'var(--green-glow)';
                tierBadge.style.background = 'var(--green-dim)';
            }

            // Score Breakdown
            const breakdownList = document.getElementById('score-breakdown-list');
            breakdownList.innerHTML = '';
            const breakdownItems = report.score_breakdown || [];
            document.getElementById('factor-count-tag').innerText = `${breakdownItems.length} FACTOR${breakdownItems.length === 1 ? '' : 'S'}`;

            if (breakdownItems.length === 0) {
                breakdownList.innerHTML = '<div style="color: var(--text-muted); font-size: 12px; font-family: var(--font-code); padding: 8px;">No adverse factor points contributed to this investigation.</div>';
            } else {
                breakdownItems.forEach(item => {
                    const div = document.createElement('div');
                    div.className = 'factor-item';
                    div.innerHTML = `
                        <div class="factor-head">
                            <span class="factor-name"><i class="fa-solid fa-shield-halved"></i> ${escapeHtml(item.factor)} (Weight: ${item.weight || '18.0'})</span>
                            <span class="factor-pts">+${typeof item.points === 'number' ? item.points.toFixed(1) : item.points} PTS</span>
                        </div>
                        <div class="factor-reason">${escapeHtml(item.reason || '')}</div>
                        ${item.evidence_id ? `<div style="font-family: var(--font-code); font-size: 11px; color: var(--text-muted);">Ref: <code>${escapeHtml(item.evidence_id)}</code></div>` : ''}
                    `;
                    breakdownList.appendChild(div);
                });
            }

            // MITRE ATT&CK Mappings
            const mitreContainer = document.getElementById('mitre-list');
            mitreContainer.innerHTML = '';
            const mitreMappings = report.mitre_attack_mapping || [];
            if (mitreMappings.length === 0) {
                mitreContainer.innerHTML = '<div style="color: var(--text-muted); font-size: 12px; font-family: var(--font-code);">No MITRE ATT&CK adversarial techniques mapped.</div>';
            } else {
                mitreMappings.forEach(m => {
                    const chip = document.createElement('div');
                    chip.className = 'mitre-chip';
                    chip.innerHTML = `<i class="fa-solid fa-triangle-exclamation"></i> <strong>${escapeHtml(m.id)}</strong>: ${escapeHtml(m.name)} (${escapeHtml(m.tactic || 'Technique')})`;
                    mitreContainer.appendChild(chip);
                });
            }

            // IoCs
            const iocsContainer = document.getElementById('iocs-list');
            iocsContainer.innerHTML = '';
            const iocs = report.indicators_of_compromise || {};
            let iocCount = 0;

            ['urls', 'emails', 'domains', 'ips', 'hashes'].forEach(type => {
                const list = iocs[type] || [];
                list.forEach(val => {
                    iocCount++;
                    const chip = document.createElement('div');
                    chip.className = 'ioc-chip';
                    chip.innerHTML = `<strong>${type.toUpperCase().slice(0, -1)}:</strong> ${escapeHtml(val)}`;
                    iocsContainer.appendChild(chip);
                });
            });

            if (iocCount === 0) {
                iocsContainer.innerHTML = '<div style="color: var(--text-muted); font-size: 12px; font-family: var(--font-code);">No suspicious Indicators of Compromise (IoCs) extracted.</div>';
            }

            // Analyst Notes & Executive Summary
            const notesBox = document.getElementById('analyst-notes-content');
            let notesText = '';
            if (report.executive_summary) {
                notesText += "[EXECUTIVE SUMMARY]\\n" + report.executive_summary + "\\n\\n";
            }
            if (report.analyst_notes && Array.isArray(report.analyst_notes)) {
                notesText += "[SOC INVESTIGATION NOTES]\\n" + report.analyst_notes.join("\\n");
            } else if (typeof report.analyst_notes === 'string') {
                notesText += report.analyst_notes;
            }
            notesBox.innerText = notesText || "Automated multi-step investigation completed.";

            // Evidence Collection Explorer
            const evidenceContainer = document.getElementById('evidence-list');
            evidenceContainer.innerHTML = '';
            const evidences = data.evidence || [];
            document.getElementById('evidence-count-tag').innerText = `${evidences.length} ITEM${evidences.length === 1 ? '' : 'S'}`;

            if (evidences.length === 0) {
                evidenceContainer.innerHTML = '<div style="color: var(--text-muted); font-size: 12px; font-family: var(--font-code); padding: 8px;">No evidence records collected.</div>';
            } else {
                evidences.forEach(ev => {
                    const sev = (ev.severity || 'INFO').toUpperCase();
                    const color = (sev === 'CRITICAL' || sev === 'HIGH') ? 'var(--red-glow)' : (sev === 'MEDIUM' ? 'var(--amber-glow)' : 'var(--cyan-glow)');
                    const div = document.createElement('div');
                    div.className = 'evidence-item';
                    div.innerHTML = `
                        <div class="evidence-head">
                            <span style="color: var(--cyan-glow); font-weight: 600;"><i class="fa-solid fa-crosshairs"></i> ${escapeHtml(ev.title || ev.category || 'EVIDENCE')}</span>
                            <span style="color: ${color}; font-weight: 700;">${sev}</span>
                        </div>
                        <div class="evidence-desc">${escapeHtml(ev.description || '')}</div>
                        <div style="font-family: var(--font-code); font-size: 11px; color: var(--text-muted); display: flex; justify-content: space-between;">
                            <span>Source: <code>${escapeHtml(ev.source || 'agent')}</code></span>
                            <span>ID: <code>${escapeHtml(ev.evidence_id || '')}</code></span>
                        </div>
                    `;
                    evidenceContainer.appendChild(div);
                });
            }

            document.getElementById('json-raw-view').innerText = JSON.stringify(data, null, 2);
        }

        function toggleJsonView() {
            const pre = document.getElementById('json-raw-view');
            pre.style.display = pre.style.display === 'none' ? 'block' : 'none';
        }

        let currentModalIncident = null;

        async function openIncidentDetailModal(id) {
            await ensureAuthToken();
            const modal = document.getElementById('incident-modal');
            const loading = document.getElementById('incident-modal-loading');
            const content = document.getElementById('incident-modal-content');

            modal.classList.add('active');
            loading.style.display = 'flex';
            content.style.display = 'none';

            try {
                const res = await fetch(`/api/v1/investigate/${id}`, {
                    headers: { 'Authorization': 'Bearer ' + activeAuthToken }
                });

                if (!res.ok) {
                    loading.innerHTML = `<div style="color: var(--red-glow);">Failed to load record (${res.status})</div>`;
                    return;
                }

                const data = await res.json();
                currentModalIncident = data;

                document.getElementById('inc-modal-id').innerText = data.id || 'N/A';
                document.getElementById('inc-modal-org').innerText = data.org_id || 'default_tenant';
                document.getElementById('inc-modal-sender').innerText = data.sender || 'N/A';
                document.getElementById('inc-modal-subject').innerText = data.subject || 'N/A';

                const verdictEl = document.getElementById('inc-modal-verdict');
                verdictEl.innerText = (data.verdict || 'UNKNOWN').toUpperCase();
                const isMal = data.verdict === 'PHISHING / MALICIOUS' || data.verdict === 'MALICIOUS' || data.risk_level === 'CRITICAL' || data.risk_level === 'HIGH' || data.risk_level === 'critical' || data.risk_level === 'high';
                verdictEl.style.color = isMal ? 'var(--red-glow)' : 'var(--green-glow)';

                const riskEl = document.getElementById('inc-modal-risk');
                riskEl.innerText = (data.risk_level || 'N/A').toUpperCase();
                riskEl.style.color = isMal ? 'var(--red-glow)' : 'var(--green-glow)';

                const conf = typeof data.confidence === 'number' ? (data.confidence * 100).toFixed(1) + '%' : 'N/A';
                document.getElementById('inc-modal-conf').innerText = conf;

                document.getElementById('inc-modal-duration').innerText = data.duration_ms ? `${data.duration_ms} ms` : 'N/A';
                document.getElementById('inc-modal-time').innerText = data.created_at || 'N/A';

                loading.style.display = 'none';
                content.style.display = 'flex';
            } catch (err) {
                loading.innerHTML = `<div style="color: var(--red-glow);">Error: ${escapeHtml(err.message)}</div>`;
            }
        }

        function closeIncidentModal() {
            document.getElementById('incident-modal').classList.remove('active');
        }

        function reanalyzeFromModal() {
            if (!currentModalIncident) return;
            document.getElementById('input-sender').value = currentModalIncident.sender || '';
            document.getElementById('input-subject').value = currentModalIncident.subject || '';
            document.getElementById('input-body').value = currentModalIncident.subject ? `Subject: ${currentModalIncident.subject}\nSender: ${currentModalIncident.sender}` : '';
            closeIncidentModal();
            switchTab('scanner');
        }

        // Fetch History
        async function fetchHistory() {
            await ensureAuthToken();
            const tbody = document.getElementById('history-tbody');
            tbody.innerHTML = '<tr><td colspan="7" style="text-align: center;">Fetching incident records...</td></tr>';

            try {
                const res = await fetch('/api/v1/investigate', {
                    headers: { 'Authorization': 'Bearer ' + activeAuthToken }
                });

                if (!res.ok) {
                    tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--red-glow);">History unavailable</td></tr>';
                    return;
                }

                const data = await res.json();
                if (!Array.isArray(data) || data.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="7" style="text-align: center;">No investigation records found in current session.</td></tr>';
                    return;
                }

                tbody.innerHTML = data.map(item => `
                    <tr>
                        <td><code>${escapeHtml(item.id || item.investigation_id || 'N/A')}</code></td>
                        <td>${escapeHtml(item.sender || 'N/A')}</td>
                        <td>${escapeHtml(item.subject || 'N/A')}</td>
                        <td><span style="color: ${item.verdict === 'PHISHING / MALICIOUS' || item.verdict === 'MALICIOUS' || item.risk_level === 'CRITICAL' || item.risk_level === 'HIGH' || item.risk_level === 'critical' || item.risk_level === 'high' ? 'var(--red-glow)' : 'var(--green-glow)'}">${escapeHtml(item.verdict || 'N/A')}</span></td>
                        <td><span style="font-family: var(--font-code); font-size: 11px;">${escapeHtml(item.risk_level || 'N/A')}</span></td>
                        <td>${item.duration_ms ? item.duration_ms + ' ms' : 'N/A'}</td>
                        <td>
                            <button class="hud-btn" style="font-size: 11px; padding: 4px 10px;" onclick="openIncidentDetailModal('${escapeHtml(item.id || item.investigation_id)}')">
                                <i class="fa-solid fa-eye"></i> INSPECT
                            </button>
                        </td>
                    </tr>
                `).join('');
            } catch (err) {
                tbody.innerHTML = '<tr><td colspan="7" style="text-align: center;">Error fetching history</td></tr>';
            }
        }

        // Search Semantic Vector Memory
        async function searchMemory() {
            await ensureAuthToken();
            const query = document.getElementById('memory-search-input').value.trim();
            if (!query) return;

            const container = document.getElementById('memory-results');
            container.innerHTML = '<div style="font-family: var(--font-code); color: var(--text-cyber);"><i class="fa-solid fa-spinner fa-spin"></i> Querying pgvector semantic index...</div>';

            try {
                const res = await fetch(`/api/v1/memory/search?q=${encodeURIComponent(query)}`, {
                    method: 'GET',
                    headers: {
                        'Authorization': 'Bearer ' + activeAuthToken
                    }
                });

                if (res.status === 401) {
                    await requestNewDemoToken();
                    return searchMemory();
                }

                if (!res.ok) {
                    container.innerHTML = '<div style="color: var(--red-glow);">Semantic memory search returned status ' + res.status + '.</div>';
                    return;
                }

                const data = await res.json();
                const items = Array.isArray(data) ? data : (data.results || data.items || []);
                if (items.length === 0) {
                    container.innerHTML = '<div style="color: var(--text-muted); font-size: 13px; font-family: var(--font-code); padding: 12px 0;">No vector memory matches found for query.</div>';
                    return;
                }

                container.innerHTML = items.map((r, idx) => {
                    const rec = r.record || {};
                    const scoreVal = typeof r.similarity_score === 'number' ? (r.similarity_score * 100).toFixed(1) : (typeof r.similarity === 'number' ? (r.similarity * 100).toFixed(1) : (typeof r.score === 'number' ? (r.score * 100).toFixed(1) : 'MATCH'));
                    const recId = rec.memory_id || r.memory_id || rec.id || r.id || `rec_${idx + 1}`;
                    const memType = (r.memory_type || rec.memory_type || 'EVIDENCE').toUpperCase();
                    const title = rec.title || (rec.category ? rec.category.replace(/_/g, ' ').toUpperCase() : '') || (rec.pattern_rules ? (rec.pattern_rules.category || 'THREAT PATTERN').toUpperCase() : 'THREAT MEMORY RECORD');
                    const desc = rec.description || (rec.pattern_rules ? rec.pattern_rules.detail : '') || rec.content || r.content || r.text || JSON.stringify(rec);
                    const sev = (rec.severity || (rec.pattern_rules ? rec.pattern_rules.severity : '') || 'INFO').toUpperCase();
                    const sevColor = (sev === 'CRITICAL' || sev === 'HIGH') ? 'var(--red-glow)' : (sev === 'MEDIUM' ? 'var(--amber-glow)' : 'var(--cyan-glow)');

                    return `
                    <div class="factor-item" style="border-left: 3px solid var(--cyan-glow); background: rgba(3,7,18,0.7); padding: 14px; border-radius: 6px; margin-bottom: 8px;">
                        <div class="factor-head" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                            <span class="factor-name" style="color: var(--cyan-glow); font-weight: 700;">
                                <i class="fa-solid fa-brain"></i> SIMILARITY: ${scoreVal}% &bull; <span style="font-size: 11px; opacity: 0.8;">${escapeHtml(memType)}</span>
                            </span>
                            <span style="font-family: var(--font-code); font-size: 11px; color: var(--text-muted);">
                                ID: <code>${escapeHtml(recId)}</code>
                            </span>
                        </div>
                        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px;">
                            <span style="font-weight: 600; color: #fff; font-size: 13px;">${escapeHtml(title)}</span>
                            <span style="font-family: var(--font-code); font-size: 11px; font-weight: 700; color: ${sevColor}; background: rgba(255,255,255,0.05); padding: 2px 8px; border-radius: 3px;">${escapeHtml(sev)}</span>
                        </div>
                        <div class="factor-reason" style="color: #cbd5e1; font-size: 12.5px; line-height: 1.5; margin-bottom: 6px;">${escapeHtml(desc)}</div>
                        <div style="font-family: var(--font-code); font-size: 11px; color: var(--text-muted); display: flex; gap: 14px; flex-wrap: wrap;">
                            ${rec.source_tool ? `<span>Source: <code>${escapeHtml(rec.source_tool)}</code></span>` : ''}
                            ${rec.evidence_id ? `<span>Evidence Ref: <code>${escapeHtml(rec.evidence_id)}</code></span>` : ''}
                            ${rec.created_at ? `<span>Indexed: <code>${escapeHtml(rec.created_at.slice(0, 19).replace('T', ' '))}</code></span>` : ''}
                        </div>
                    </div>`;
                }).join('');
            } catch (err) {
                container.innerHTML = '<div style="color: var(--red-glow);">Error executing vector query: ' + escapeHtml(err.message) + '</div>';
            }
        }

        // Fetch Telemetry
        async function fetchTelemetry() {
            await checkSystemHealth();
            try {
                const res = await fetch('/metrics');
                if (res.ok) {
                    const data = await res.json();
                    if (data.database_connected !== undefined) {
                        document.getElementById('metric-db').innerText = data.database_connected ? 'CONNECTED' : 'DISCONNECTED';
                    }
                }
            } catch (err) {
                console.warn("Telemetry fetch error:", err);
            }
        }

        // Init page setup
        ensureAuthToken();
        checkSystemHealth();
        checkGmailStatus();
        setInterval(checkSystemHealth, 15000);

        // Check if redirected from Google OAuth
        const urlParams = new URLSearchParams(window.location.search);
        if (urlParams.get('gmail_connected')) {
            switchTab('gmail');
        }
    </script>
</body>
</html>
"""
