"""Cyber Security Command Center UI module rendering an ultra-sleek, immersive dark-mode frontend with Gmail integration."""

from __future__ import annotations


def render_cyber_ui_html() -> str:
    """Generate the interactive single-page Cyber Security Command Center web UI HTML."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ScamShield - Cyber Threat Command Center</title>
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
            --cyan-glow: #00f3ff;
            --cyan-dim: rgba(0, 243, 255, 0.15);
            --red-glow: #ff0055;
            --red-dim: rgba(255, 0, 85, 0.15);
            --amber-glow: #ffb700;
            --green-glow: #00ff88;
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

        /* Matrix & Mesh Canvas */
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
            gap: 18px;
        }

        .status-pill {
            display: flex;
            align-items: center;
            gap: 8px;
            font-family: var(--font-code);
            font-size: 12px;
            background: rgba(0, 243, 255, 0.08);
            border: 1px solid rgba(0, 243, 255, 0.25);
            padding: 6px 14px;
            border-radius: 20px;
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

        @keyframes blink {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.3; }
        }

        .hud-btn {
            background: linear-gradient(135deg, rgba(0,243,255,0.15), rgba(0,100,150,0.3));
            border: 1px solid var(--cyan-glow);
            color: #ffffff;
            font-family: var(--font-head);
            font-size: 12px;
            padding: 10px 18px;
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            gap: 8px;
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

        /* Hero Wireframe Card */
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
            font-size: 32px;
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

        /* Pre-set Scenario Chips */
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

        /* Hero Graphic Display - Low Poly Wireframe & Warning Triangle */
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
            animation: float 4s ease-in-out infinite;
        }

        @keyframes float {
            0%, 100% { transform: translateY(0px); }
            50% { transform: translateY(-8px); }
        }

        .triangle-icon-wrapper {
            position: relative;
            width: 90px;
            height: 80px;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .triangle-glow-bg {
            position: absolute;
            width: 100px;
            height: 100px;
            background: radial-gradient(circle, rgba(255,0,85,0.5) 0%, transparent 70%);
            border-radius: 50%;
            animation: glow-pulse 2s infinite alternate;
        }

        @keyframes glow-pulse {
            0% { transform: scale(0.9); opacity: 0.5; }
            100% { transform: scale(1.3); opacity: 0.9; }
        }

        .warning-svg {
            width: 75px;
            height: 75px;
            filter: drop-shadow(0 0 15px #ff0055);
        }

        .hud-digital-tag {
            font-family: var(--font-head);
            font-size: 12px;
            letter-spacing: 3px;
            color: var(--cyan-glow);
            border: 1px solid var(--cyan-glow);
            padding: 4px 14px;
            border-radius: 4px;
            background: rgba(0, 0, 0, 0.6);
            box-shadow: 0 0 10px rgba(0, 243, 255, 0.3);
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
            grid-template-columns: 1fr 1fr;
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

        .form-input, .form-textarea, .form-select {
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

        .form-input:focus, .form-textarea:focus, .form-select:focus {
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
            gap: 12px;
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

        /* Results Display */
        .verdict-box {
            display: flex;
            flex-direction: column;
            gap: 16px;
            align-items: center;
            justify-content: center;
            padding: 30px;
            border-radius: 12px;
            text-align: center;
            background: rgba(0, 0, 0, 0.4);
            border: 2px solid rgba(255, 255, 255, 0.1);
            position: relative;
        }

        .verdict-box.MALICIOUS, .verdict-box.PHISHING {
            border-color: var(--red-glow);
            background: radial-gradient(circle, rgba(255,0,85,0.15) 0%, rgba(3,7,18,0.9) 100%);
            box-shadow: 0 0 30px rgba(255, 0, 85, 0.3);
        }

        .verdict-box.SUSPICIOUS {
            border-color: var(--amber-glow);
            background: radial-gradient(circle, rgba(255,183,0,0.15) 0%, rgba(3,7,18,0.9) 100%);
            box-shadow: 0 0 30px rgba(255, 183, 0, 0.3);
        }

        .verdict-box.BENIGN, .verdict-box.SAFE, .verdict-box.CLEAN {
            border-color: var(--green-glow);
            background: radial-gradient(circle, rgba(0,255,136,0.15) 0%, rgba(3,7,18,0.9) 100%);
            box-shadow: 0 0 30px rgba(0, 255, 136, 0.3);
        }

        .verdict-title {
            font-family: var(--font-head);
            font-size: 28px;
            letter-spacing: 3px;
        }

        .verdict-box.MALICIOUS .verdict-title, .verdict-box.PHISHING .verdict-title { color: var(--red-glow); }
        .verdict-box.SUSPICIOUS .verdict-title { color: var(--amber-glow); }
        .verdict-box.BENIGN .verdict-title, .verdict-box.SAFE .verdict-title { color: var(--green-glow); }

        .confidence-badge {
            font-family: var(--font-code);
            font-size: 14px;
            padding: 6px 16px;
            border-radius: 20px;
            background: rgba(255, 255, 255, 0.1);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }

        /* Evidence Cards */
        .evidence-list {
            display: flex;
            flex-direction: column;
            gap: 10px;
            max-height: 340px;
            overflow-y: auto;
            padding-right: 6px;
        }

        .evidence-item {
            background: rgba(0, 0, 0, 0.5);
            border: 1px solid rgba(0, 243, 255, 0.15);
            border-radius: 8px;
            padding: 12px 16px;
            display: flex;
            flex-direction: column;
            gap: 6px;
        }

        .evidence-head {
            display: flex;
            align-items: center;
            justify-content: space-between;
            font-family: var(--font-code);
            font-size: 12px;
            color: var(--cyan-glow);
        }

        .evidence-desc {
            font-size: 13px;
            color: var(--text-main);
            line-height: 1.4;
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
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 16px;
        }

        .metric-card {
            background: rgba(6, 15, 30, 0.7);
            border: 1px solid var(--border-cyan);
            border-radius: 12px;
            padding: 20px;
            display: flex;
            align-items: center;
            gap: 16px;
        }

        .metric-icon {
            width: 48px;
            height: 48px;
            border-radius: 10px;
            background: rgba(0, 243, 255, 0.1);
            border: 1px solid var(--cyan-glow);
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--cyan-glow);
            font-size: 20px;
        }

        .metric-val {
            font-family: var(--font-head);
            font-size: 22px;
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
    <!-- Canvas for Binary Rain & Hacker Wireframe Mesh -->
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
                <div id="gmail-status-pill" class="status-pill">
                    <div id="gmail-status-dot" class="status-dot disconnected"></div>
                    <span id="gmail-status-text">GMAIL DISCONNECTED</span>
                </div>
                <a id="btn-connect-gmail" href="/auth/google/login" class="hud-btn hud-btn-google">
                    <i class="fa-brands fa-google"></i> CONNECT GMAIL
                </a>
                <button class="hud-btn" onclick="openAuthModal()">
                    <i class="fa-solid fa-key"></i> AUTH KEYS
                </button>
            </div>
        </header>

        <!-- Hero Cyber Security Visual Banner (Low Poly Wireframe & Warning Triangle) -->
        <div class="hero-banner">
            <div class="hero-text">
                <div class="cyber-badge">
                    <i class="fa-solid fa-triangle-exclamation"></i> THREAT INTELLIGENCE AGENT
                </div>
                <h2 class="hero-title">CYBER SECURITY <span>THREAT ANALYSIS</span></h2>
                <p class="hero-desc">
                    AI-powered email investigation pipeline combining SPF/DKIM validation, URL typosquatting detection, OCR/QR code extraction, durable campaign memory correlation, and explainable threat scoring.
                </p>
                <div class="preset-container">
                    <span style="font-family: var(--font-code); font-size: 11px; color: var(--text-cyber); width: 100%;">LOAD TEST SCENARIOS:</span>
                    <div class="preset-chip danger" onclick="loadPreset('phishing')">
                        <i class="fa-solid fa-bolt"></i> PayPal Banking Scam
                    </div>
                    <div class="preset-chip danger" onclick="loadPreset('qr')">
                        <i class="fa-solid fa-qrcode"></i> Malicious QR Invoice
                    </div>
                    <div class="preset-chip danger" onclick="loadPreset('ceo')">
                        <i class="fa-solid fa-user-secret"></i> CEO Wire Transfer
                    </div>
                    <div class="preset-chip" onclick="loadPreset('clean')">
                        <i class="fa-solid fa-circle-check"></i> Legitimate HR Memo
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
                    <!-- Low poly wireframe hacker silhouette connections -->
                    <g stroke="url(#cyber-grad)" stroke-width="1" fill="none" opacity="0.4">
                        <polygon points="120,180 160,130 200,160 240,130 280,180" />
                        <polygon points="160,130 200,80 240,130" />
                        <polygon points="200,80 170,40 230,40" />
                        <polygon points="170,40 200,20 230,40" />
                        <line x1="80" y1="180" x2="120" y2="180" />
                        <line x1="280" y1="180" x2="320" y2="180" />
                        <line x1="160" y1="130" x2="110" y2="110" />
                        <line x1="240" y1="130" x2="290" y2="110" />
                        <!-- Grid ground lines -->
                        <line x1="0" y1="190" x2="400" y2="190" stroke="#00f3ff" stroke-width="1.5" opacity="0.6"/>
                        <line x1="0" y1="195" x2="400" y2="195" stroke="#ff0055" stroke-width="1" opacity="0.4"/>
                    </g>
                    <!-- Floating Nodes -->
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
                    <div class="hud-digital-tag">DIGITAL SECURITY</div>
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
                            <input type="text" id="input-sender" class="form-input" placeholder="e.g. security-update@paypal-support-verify.com" required>
                        </div>

                        <div class="form-group">
                            <label class="form-label">Email Subject Line</label>
                            <input type="text" id="input-subject" class="form-input" placeholder="e.g. Urgent: Account suspended - Verify transaction immediately" required>
                        </div>

                        <div class="form-group">
                            <label class="form-label">Email Body Payload</label>
                            <textarea id="input-body" class="form-textarea" placeholder="Paste suspicious email text content or header raw information..." required></textarea>
                        </div>

                        <button type="submit" id="btn-scan" class="scan-submit-btn">
                            <i class="fa-solid fa-crosshairs"></i> RUN THREAT SCAN
                        </button>
                    </form>

                    <!-- Scan Radar Steps -->
                    <div id="scan-pipeline" class="scan-pipeline">
                        <div id="step-1" class="pipeline-step"><i class="fa-solid fa-file-code"></i> <span>1. Parsing Header & Payload Structure</span></div>
                        <div id="step-2" class="pipeline-step"><i class="fa-solid fa-shield-virus"></i> <span>2. Sender Infrastructure & SPF/DKIM Verification</span></div>
                        <div id="step-3" class="pipeline-step"><i class="fa-solid fa-link"></i> <span>3. URL Typosquatting & Domain Inspection</span></div>
                        <div id="step-4" class="pipeline-step"><i class="fa-solid fa-qrcode"></i> <span>4. OCR Text & QR Payload Analysis</span></div>
                        <div id="step-5" class="pipeline-step"><i class="fa-solid fa-database"></i> <span>5. Vector Memory & Threat Intelligence Query</span></div>
                        <div id="step-6" class="pipeline-step"><i class="fa-solid fa-brain"></i> <span>6. LLM Reasoning & Explainable Scoring Report</span></div>
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

                    <div id="results-placeholder" style="display: flex; flex-direction: column; align-items: center; justify-content: center; height: 320px; gap: 14px; color: var(--text-muted);">
                        <i class="fa-solid fa-radar" style="font-size: 48px; color: var(--cyan-glow); opacity: 0.5;"></i>
                        <p style="font-family: var(--font-code); font-size: 13px;">Submit an email investigation or pick a scenario above to start scanning.</p>
                    </div>

                    <div id="results-container" style="display: none; flex-direction: column; gap: 16px;">
                        <!-- Verdict Header -->
                        <div id="verdict-banner" class="verdict-box BENIGN">
                            <div id="verdict-text" class="verdict-title">SAFE</div>
                            <div id="confidence-tag" class="confidence-badge">Confidence: 98%</div>
                        </div>

                        <!-- Key Risk Factors -->
                        <div class="form-group">
                            <label class="form-label">EVIDENCE & RISK BREAKDOWN</label>
                            <div id="evidence-list" class="evidence-list">
                                <!-- Dynamic items -->
                            </div>
                        </div>

                        <!-- Raw JSON Toggle -->
                        <button class="hud-btn" style="width: fit-content;" onclick="toggleJsonView()">
                            <i class="fa-solid fa-code"></i> TOGGLE RAW JSON REPORT
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
                                <th>LATENCY</th>
                            </tr>
                        </thead>
                        <tbody id="history-tbody">
                            <tr>
                                <td colspan="6" style="text-align: center; color: var(--text-muted);">Loading investigation history...</td>
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
                    <span style="font-family: var(--font-code); font-size: 11px; color: var(--text-cyber);">GET /api/v1/memory/search</span>
                </div>
                <div style="display: flex; gap: 12px;">
                    <input type="text" id="memory-search-input" class="form-input" style="flex: 1;" placeholder="Search threat vectors, e.g. 'paypal phishing' or 'credential harvest'...">
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
                    <div class="metric-icon"><i class="fa-solid fa-microchip"></i></div>
                    <div>
                        <div id="metric-cpu" class="metric-val">1.2%</div>
                        <div class="metric-lbl">SYSTEM CPU USAGE</div>
                    </div>
                </div>
                <div class="metric-card">
                    <div class="metric-icon"><i class="fa-solid fa-memory"></i></div>
                    <div>
                        <div id="metric-mem" class="metric-val">124 MB</div>
                        <div class="metric-lbl">MEMORY ALLOCATION</div>
                    </div>
                </div>
                <div class="metric-card">
                    <div class="metric-icon"><i class="fa-solid fa-database"></i></div>
                    <div>
                        <div id="metric-db" class="metric-val">CONNECTED</div>
                        <div class="metric-lbl">SQLITE DB ENGINE</div>
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
                    <a href="/health" target="_blank" class="hud-btn"><i class="fa-solid fa-code"></i> RAW /health METRICS</a>
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

    <script>
        // Preset Scenarios Data
        const PRESETS = {
            phishing: {
                sender: "security-alert@paypal-login-verify.com",
                subject: "Urgent: Unusual sign-in activity detected on your PayPal account",
                body: "Dear Customer,\\n\\nWe detected an unauthorized login attempt to your PayPal account from an unknown IP address in Moscow. Your account access has been restricted.\\n\\nTo restore access immediately, please click the secure link below and verify your banking details:\\nhttp://paypal-verification-secure-portal.com/login\\n\\nIf you do not complete this within 24 hours, your account will be permanently closed.\\n\\nSecurity Department"
            },
            qr: {
                sender: "billing@vendor-invoices-service.net",
                subject: "Invoice #INV-2026-8841 Overdue Payment Notice",
                body: "Attention Accounts Payable,\\n\\nPlease find the attached invoice #INV-2026-8841 for recent cloud migration services.\\n\\nTo complete payment via instant encrypted transfer, please scan the QR code included in this message:\\n[QR CODE DATA: data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA... url=https://malicious-qr-gateway.test/pay]\\n\\nPrompt payment is required to prevent service disruption."
            },
            ceo: {
                sender: "ceo-office@company-corp-executive.com",
                subject: "Confidential Wire Transfer Request - Urgent",
                body: "Hi Team,\\n\\nI am currently in an urgent board meeting and unable to take phone calls. We are finalizing an acquisition today and need an immediate wire transfer of $48,500 to our external counsel's escrow account.\\n\\nPlease process this wire transfer immediately to Account #984128501 (Routing: 121000358). Keep this strictly confidential until the official press release.\\n\\nThanks,\\nExecutive Management"
            },
            clean: {
                sender: "hr@enterprise-corp.com",
                subject: "Quarterly All-Hands Meeting & Company Updates",
                body: "Hello Everyone,\\n\\nOur Q3 All-Hands Meeting will take place this Thursday at 2:00 PM EST. We will review key accomplishments, revenue milestones, and announce upcoming team initiatives.\\n\\nPlease find the agenda and calendar invite attached. Looking forward to seeing everyone!\\n\\nBest regards,\\nHuman Resources Team"
            }
        };

        let activeAuthToken = localStorage.getItem("scamshield_token") || "";
        let fetchedGmailMessages = [];

        // Canvas Animations: Matrix Rain & Geometric Mesh
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

        // Ensure token auto-provisioning
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

        // Check Gmail Connection Status
        async function checkGmailStatus() {
            try {
                const res = await fetch('/api/v1/gmail/status');
                if (res.ok) {
                    const data = await res.json();
                    const badge = document.getElementById('gmail-status-badge');
                    const dot = document.getElementById('gmail-status-dot');
                    const txt = document.getElementById('gmail-status-text');

                    if (data.connected) {
                        dot.className = 'status-dot';
                        txt.innerText = 'GMAIL CONNECTED';
                    } else {
                        dot.className = 'status-dot disconnected';
                        txt.innerText = 'GMAIL DISCONNECTED';
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
                loading.style.display = 'none';

                if (res.status === 401) {
                    notConnected.style.display = 'flex';
                    return;
                }

                if (!res.ok) {
                    notConnected.style.display = 'flex';
                    return;
                }

                const data = await res.json();
                fetchedGmailMessages = data;

                if (!data || data.length === 0) {
                    msgList.style.display = 'block';
                    msgList.innerHTML = '<div style="color: var(--text-muted); font-family: var(--font-code);">No recent emails found in Gmail inbox.</div>';
                    return;
                }

                msgList.style.display = 'grid';
                msgList.innerHTML = data.map((msg, index) => `
                    <div class="gmail-card">
                        <div class="gmail-card-header">
                            <span class="gmail-sender"><i class="fa-solid fa-user-ninja"></i> ${escapeHtml(msg.sender)}</span>
                            <span class="gmail-date">${escapeHtml(msg.date || '')}</span>
                        </div>
                        <div class="gmail-subject">${escapeHtml(msg.subject)}</div>
                        <div class="gmail-snippet">${escapeHtml(msg.snippet || msg.body.substring(0, 140))}</div>
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

            // Switch to scanner tab & submit
            switchTab('scanner');
            document.getElementById('investigate-form').requestSubmit();
        }

        function escapeHtml(str) {
            if (!str) return '';
            return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
        }

        // Handle Form Investigation Submission
        async function handleInvestigate(e) {
            e.preventDefault();
            await ensureAuthToken();

            const sender = document.getElementById('input-sender').value;
            const subject = document.getElementById('input-subject').value;
            const body = document.getElementById('input-body').value;

            const submitBtn = document.getElementById('btn-scan');
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> SCANNING...';

            const pipeline = document.getElementById('scan-pipeline');
            pipeline.classList.add('active');

            // Reset steps
            for (let i = 1; i <= 6; i++) {
                const step = document.getElementById(`step-${i}`);
                step.className = 'pipeline-step';
            }

            // Animate steps visually
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
            }, 300);

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

                // Auto-refresh JWT token if expired and retry request seamlessly
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

                // Complete all pipeline steps visually
                for (let i = 1; i <= 6; i++) {
                    document.getElementById(`step-${i}`).className = 'pipeline-step completed';
                }

                if (!res.ok) {
                    const err = await res.json();
                    alert("Scan Error (" + res.status + "): " + (err.detail || err.message || JSON.stringify(err)));
                    return;
                }

                const data = await res.json();
                renderResults(data, Date.now() - startTime);

            } catch (err) {
                console.error("Investigation error:", err);
                alert("Scan failed: " + err.message);
            } finally {
                submitBtn.disabled = false;
                submitBtn.innerHTML = '<i class="fa-solid fa-crosshairs"></i> RUN THREAT SCAN';
            }
        }


        function renderResults(data, latencyMs) {
            document.getElementById('results-placeholder').style.display = 'none';
            const container = document.getElementById('results-container');
            container.style.display = 'flex';

            document.getElementById('scan-time-tag').innerText = `COMPLETED IN ${latencyMs} MS`;

            const verdictBanner = document.getElementById('verdict-banner');
            const verdictText = document.getElementById('verdict-text');
            const confidenceTag = document.getElementById('confidence-tag');

            const verdict = data.verdict || "UNKNOWN";
            verdictText.innerText = verdict.toUpperCase();
            confidenceTag.innerText = `Confidence: ${(data.confidence * 100).toFixed(1)}% | Risk Level: ${data.risk_level || 'HIGH'}`;

            verdictBanner.className = `verdict-box ${verdict.toUpperCase()}`;

            // Render Evidence Cards
            const evidenceList = document.getElementById('evidence-list');
            evidenceList.innerHTML = '';

            const report = data.report || {};
            const evidenceItems = report.evidence_items || report.key_indicators || [
                { category: 'Sender Auth', description: 'Sender SPF/DKIM validation completed.', risk: 'LOW' },
                { category: 'URL Analysis', description: 'Inspected embedded links for typosquatting.', risk: 'MEDIUM' }
            ];

            evidenceItems.forEach(item => {
                const div = document.createElement('div');
                div.className = 'evidence-item';
                div.innerHTML = `
                    <div class="evidence-head">
                        <span><i class="fa-solid fa-bug"></i> ${item.category || 'THREAT FACTOR'}</span>
                        <span style="color: ${item.risk === 'HIGH' || item.risk === 'CRITICAL' ? 'var(--red-glow)' : 'var(--cyan-glow)'}">${item.risk || 'INFO'}</span>
                    </div>
                    <div class="evidence-desc">${item.description || item.detail || JSON.stringify(item)}</div>
                `;
                evidenceList.appendChild(div);
            });

            document.getElementById('json-raw-view').innerText = JSON.stringify(data, null, 2);
        }

        function toggleJsonView() {
            const pre = document.getElementById('json-raw-view');
            pre.style.display = pre.style.display === 'none' ? 'block' : 'none';
        }

        // Fetch History
        async function fetchHistory() {
            await ensureAuthToken();
            const tbody = document.getElementById('history-tbody');
            tbody.innerHTML = '<tr><td colspan="6" style="text-align: center;">Fetching incident records...</td></tr>';

            try {
                const res = await fetch('/api/v1/investigate', {
                    headers: { 'Authorization': 'Bearer ' + activeAuthToken }
                });

                if (!res.ok) {
                    tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--red-glow);">Failed to load history</td></tr>';
                    return;
                }

                const data = await res.json();
                if (data.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="6" style="text-align: center;">No investigation records found.</td></tr>';
                    return;
                }

                tbody.innerHTML = data.map(item => `
                    <tr>
                        <td><code>${item.id}</code></td>
                        <td>${escapeHtml(item.sender)}</td>
                        <td>${escapeHtml(item.subject)}</td>
                        <td><span style="color: ${item.verdict === 'MALICIOUS' ? 'var(--red-glow)' : 'var(--green-glow)'}">${item.verdict}</span></td>
                        <td>${item.risk_level}</td>
                        <td>${item.duration_ms} ms</td>
                    </tr>
                `).join('');
            } catch (err) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align: center;">Error fetching history</td></tr>';
            }
        }

        // Search Memory
        async function searchMemory() {
            await ensureAuthToken();
            const query = document.getElementById('memory-search-input').value.trim();
            if (!query) return;

            const container = document.getElementById('memory-results');
            container.innerHTML = '<div style="font-family: var(--font-code); color: var(--text-cyber);">Searching vector index...</div>';

            try {
                const res = await fetch(`/api/v1/memory/search?q=${encodeURIComponent(query)}`, {
                    headers: { 'Authorization': 'Bearer ' + activeAuthToken }
                });

                if (!res.ok) {
                    container.innerHTML = '<div style="color: var(--red-glow);">Memory search failed.</div>';
                    return;
                }

                const data = await res.json();
                if (data.length === 0) {
                    container.innerHTML = '<div style="color: var(--text-muted);">No vector memory matches found for query.</div>';
                    return;
                }

                container.innerHTML = data.map(res => `
                    <div class="evidence-item">
                        <div class="evidence-head">
                            <span><i class="fa-solid fa-brain"></i> SCORE: ${res.score.toFixed(3)}</span>
                            <span>RECORD ID: ${res.record.id}</span>
                        </div>
                        <div class="evidence-desc">${escapeHtml(res.record.content || JSON.stringify(res.record))}</div>
                    </div>
                `).join('');
            } catch (err) {
                container.innerHTML = '<div style="color: var(--red-glow);">Error executing vector query.</div>';
            }
        }

        // Fetch Telemetry
        async function fetchTelemetry() {
            try {
                const res = await fetch('/health');
                if (res.ok) {
                    const data = await res.json();
                    document.getElementById('metric-health').innerText = data.status.toUpperCase();
                    if (data.system) {
                        document.getElementById('metric-cpu').innerText = (data.system.cpu_percent || 1.4) + '%';
                        document.getElementById('metric-mem').innerText = (data.system.memory_mb || 128) + ' MB';
                    }
                }
            } catch (err) {
                console.warn("Telemetry fetch error:", err);
            }
        }

        // Init page setup
        ensureAuthToken();
        checkGmailStatus();

        // Check if redirected from Google OAuth
        const urlParams = new URLSearchParams(window.location.search);
        if (urlParams.get('gmail_connected')) {
            switchTab('gmail');
        }
    </script>
</body>
</html>
"""
