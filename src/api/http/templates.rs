//! Embedded HTML templates for the web dashboard.
//! AXIOM Design System - Industrial-Military Visual Language

/// Main dashboard HTML template.
pub const HOME: &str = r#"<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>DAZHBOG // FUNCTION INDEX TERMINAL</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800;900&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        /* ═══════════════════════════════════════════════════════════════
           AXIOM DESIGN SYSTEM - Industrial Military Visual Language
           Classification: OPERATIONAL // Document: DZB-SYS-001
           ═══════════════════════════════════════════════════════════════ */
        
        :root {
            /* Base Colors - Control Room Atmosphere */
            --bg-void: #050505;
            --bg-base: #0a0a0a;
            --bg-panel: #0f0f0f;
            --bg-element: #141414;
            --bg-elevated: #1a1a1a;
            
            /* Borders & Lines */
            --border-dim: #1f1f1f;
            --border-subtle: #2a2a2a;
            --border-focus: #3a3a3a;
            
            /* Primary Accent - Night Vision / Active Systems */
            --accent: #00ff88;
            --accent-dim: #00cc6a;
            --accent-glow: rgba(0, 255, 136, 0.15);
            --accent-pulse: rgba(0, 255, 136, 0.4);
            
            /* Text Hierarchy */
            --text-bright: #ffffff;
            --text-primary: #e8e8e8;
            --text-secondary: #a0a0a0;
            --text-tertiary: #666666;
            --text-dim: #444444;
            
            /* State Colors - Military Warning Palette */
            --state-nominal: #00ff88;
            --state-caution: #ffaa00;
            --state-warning: #ff6600;
            --state-critical: #ff2244;
            --state-info: #0088ff;
            
            /* Typography */
            --font-display: "Inter", -apple-system, BlinkMacSystemFont, sans-serif;
            --font-mono: "JetBrains Mono", "SF Mono", "Consolas", monospace;
            
            /* Spacing Scale */
            --space-xs: 4px;
            --space-sm: 8px;
            --space-md: 16px;
            --space-lg: 24px;
            --space-xl: 32px;
            --space-2xl: 48px;
            
            /* Animation */
            --ease-out: cubic-bezier(0.16, 1, 0.3, 1);
            --ease-in-out: cubic-bezier(0.65, 0, 0.35, 1);
        }
        
        /* ─────────────────────────────────────────────────────────────
           BASE RESET & DOCUMENT
           ───────────────────────────────────────────────────────────── */
        
        *, *::before, *::after { box-sizing: border-box; }
        
        body {
            margin: 0;
            background: var(--bg-void);
            color: var(--text-primary);
            font-family: var(--font-mono);
            font-size: 13px;
            line-height: 1.5;
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
            min-height: 100vh;
            overflow-x: hidden;
        }
        
        /* Scanline overlay effect */
        body::before {
            content: "";
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: repeating-linear-gradient(
                0deg,
                transparent,
                transparent 2px,
                rgba(0, 0, 0, 0.03) 2px,
                rgba(0, 0, 0, 0.03) 4px
            );
            pointer-events: none;
            z-index: 9999;
        }
        
        /* ─────────────────────────────────────────────────────────────
           DIAGONAL STRIPE PATTERNS
           ───────────────────────────────────────────────────────────── */
        
        .stripe-pattern {
            background: repeating-linear-gradient(
                -45deg,
                transparent,
                transparent 4px,
                var(--border-dim) 4px,
                var(--border-dim) 5px
            );
        }
        
        .stripe-accent {
            background: repeating-linear-gradient(
                -45deg,
                transparent,
                transparent 3px,
                var(--accent) 3px,
                var(--accent) 4px
            );
            opacity: 0.15;
        }
        
        /* ─────────────────────────────────────────────────────────────
           DOT GRID PATTERN
           ───────────────────────────────────────────────────────────── */
        
        .dot-grid {
            background-image: radial-gradient(circle, var(--border-subtle) 1px, transparent 1px);
            background-size: 16px 16px;
        }
        
        /* ─────────────────────────────────────────────────────────────
           MAIN CONTAINER
           ───────────────────────────────────────────────────────────── */
        
        .terminal-frame {
            max-width: 1400px;
            margin: 0 auto;
            padding: var(--space-lg);
            position: relative;
        }
        
        /* Corner registration marks */
        .terminal-frame::before,
        .terminal-frame::after {
            content: "";
            position: absolute;
            width: 24px;
            height: 24px;
            border-color: var(--border-subtle);
            border-style: solid;
        }
        .terminal-frame::before {
            top: 8px;
            left: 8px;
            border-width: 2px 0 0 2px;
        }
        .terminal-frame::after {
            top: 8px;
            right: 8px;
            border-width: 2px 2px 0 0;
        }
        
        /* ─────────────────────────────────────────────────────────────
           HEADER - CLASSIFICATION BANNER
           ───────────────────────────────────────────────────────────── */
        
        .classification-bar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: var(--space-xs) var(--space-md);
            background: var(--accent);
            color: var(--bg-void);
            font-family: var(--font-mono);
            font-size: 10px;
            font-weight: 700;
            letter-spacing: 0.15em;
            text-transform: uppercase;
            margin-bottom: var(--space-md);
        }
        
        .classification-bar .doc-code {
            font-weight: 600;
            letter-spacing: 0.1em;
        }
        
        /* ─────────────────────────────────────────────────────────────
           MAIN HEADER
           ───────────────────────────────────────────────────────────── */
        
        .header-grid {
            display: grid;
            grid-template-columns: 1fr auto 1fr;
            gap: var(--space-lg);
            align-items: start;
            padding: var(--space-lg) 0;
            border-bottom: 1px solid var(--border-subtle);
            margin-bottom: var(--space-xl);
        }
        
        .header-left {
            display: flex;
            flex-direction: column;
            gap: var(--space-sm);
        }
        
        .brand-block {
            display: flex;
            align-items: center;
            gap: var(--space-md);
        }
        
        .brand-icon {
            width: 48px;
            height: 48px;
            position: relative;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .brand-icon .ring {
            position: absolute;
            border: 2px solid var(--accent);
            border-radius: 50%;
        }
        .brand-icon .ring-outer {
            width: 48px;
            height: 48px;
        }
        .brand-icon .ring-inner {
            width: 32px;
            height: 32px;
        }
        .brand-icon .core {
            width: 12px;
            height: 12px;
            background: var(--accent);
            border-radius: 50%;
            box-shadow: 0 0 20px var(--accent-pulse);
            animation: core-pulse 2s ease-in-out infinite;
        }
        
        @keyframes core-pulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.7; transform: scale(0.9); }
        }
        
        .brand-text {
            display: flex;
            flex-direction: column;
            gap: 2px;
        }
        
        .brand-name {
            font-family: var(--font-display);
            font-size: 28px;
            font-weight: 900;
            letter-spacing: 0.08em;
            color: var(--text-bright);
            line-height: 1;
        }
        
        .brand-sub {
            font-size: 10px;
            color: var(--text-tertiary);
            letter-spacing: 0.2em;
            text-transform: uppercase;
        }
        
        .serial-block {
            font-size: 10px;
            color: var(--text-dim);
            letter-spacing: 0.1em;
            display: flex;
            flex-direction: column;
            gap: 2px;
        }
        
        .serial-block span {
            display: flex;
            gap: var(--space-sm);
        }
        
        .serial-block .label {
            color: var(--text-tertiary);
            min-width: 60px;
        }
        
        /* Center status ring */
        .header-center {
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: var(--space-sm);
        }
        
        .status-ring {
            width: 80px;
            height: 80px;
            border: 3px solid var(--border-subtle);
            border-radius: 50%;
            position: relative;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .status-ring::before {
            content: "";
            position: absolute;
            inset: 6px;
            border: 1px solid var(--border-dim);
            border-radius: 50%;
        }
        
        .status-ring .status-core {
            width: 24px;
            height: 24px;
            background: var(--state-nominal);
            border-radius: 50%;
            box-shadow: 0 0 30px var(--accent-pulse), inset 0 0 10px rgba(255,255,255,0.3);
            animation: status-pulse 1.5s ease-in-out infinite;
        }
        
        .status-ring.offline .status-core {
            background: var(--state-critical);
            box-shadow: 0 0 30px rgba(255, 34, 68, 0.4);
            animation: none;
        }
        
        @keyframes status-pulse {
            0%, 100% { box-shadow: 0 0 30px var(--accent-pulse), inset 0 0 10px rgba(255,255,255,0.3); }
            50% { box-shadow: 0 0 50px var(--accent-pulse), inset 0 0 15px rgba(255,255,255,0.5); }
        }
        
        .status-label {
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.2em;
            color: var(--accent);
            text-transform: uppercase;
            display: flex;
            align-items: center;
            gap: var(--space-sm);
        }
        
        .status-label::before,
        .status-label::after {
            content: "//";
            color: var(--text-dim);
        }
        
        .status-label.offline {
            color: var(--state-critical);
        }
        
        /* Right side - coordinates and timestamp */
        .header-right {
            display: flex;
            flex-direction: column;
            align-items: flex-end;
            gap: var(--space-sm);
            text-align: right;
        }
        
        .coord-block {
            font-size: 10px;
            color: var(--text-dim);
            letter-spacing: 0.1em;
            display: flex;
            flex-direction: column;
            gap: 2px;
        }
        
        .timestamp-block {
            font-size: 18px;
            font-weight: 600;
            color: var(--text-secondary);
            font-variant-numeric: tabular-nums;
        }
        
        .uptime-block {
            font-size: 10px;
            color: var(--text-tertiary);
            letter-spacing: 0.1em;
        }
        
        /* ─────────────────────────────────────────────────────────────
           SEARCH TERMINAL
           ───────────────────────────────────────────────────────────── */
        
        .search-terminal {
            background: var(--bg-panel);
            border: 1px solid var(--border-subtle);
            padding: var(--space-lg);
            margin-bottom: var(--space-xl);
            position: relative;
        }
        
        .search-terminal::before {
            content: "QUERY INTERFACE";
            position: absolute;
            top: -8px;
            left: var(--space-md);
            background: var(--bg-panel);
            padding: 0 var(--space-sm);
            font-size: 10px;
            font-weight: 600;
            letter-spacing: 0.15em;
            color: var(--text-tertiary);
        }
        
        .search-row {
            display: flex;
            gap: var(--space-md);
            align-items: center;
        }
        
        .search-prompt {
            font-size: 14px;
            font-weight: 700;
            color: var(--accent);
            white-space: nowrap;
        }
        
        .search-input-wrap {
            flex: 1;
            position: relative;
        }
        
        .search-input {
            width: 100%;
            background: var(--bg-base);
            border: 1px solid var(--border-dim);
            padding: var(--space-md) var(--space-lg);
            font-family: var(--font-mono);
            font-size: 14px;
            color: var(--text-primary);
            outline: none;
            transition: border-color 0.15s, box-shadow 0.15s;
        }
        
        .search-input::placeholder {
            color: var(--text-dim);
        }
        
        .search-input:focus {
            border-color: var(--accent);
            box-shadow: 0 0 0 3px var(--accent-glow), inset 0 0 20px rgba(0, 255, 136, 0.03);
        }
        
        .search-kbd {
            position: absolute;
            right: var(--space-md);
            top: 50%;
            transform: translateY(-50%);
            font-size: 10px;
            font-weight: 600;
            color: var(--text-dim);
            border: 1px solid var(--border-dim);
            padding: 2px 8px;
            letter-spacing: 0.1em;
        }
        
        .search-meta {
            display: flex;
            gap: var(--space-lg);
            margin-top: var(--space-md);
            padding-top: var(--space-md);
            border-top: 1px dashed var(--border-dim);
            font-size: 10px;
            color: var(--text-dim);
            letter-spacing: 0.1em;
        }
        
        .search-meta span {
            display: flex;
            align-items: center;
            gap: var(--space-xs);
        }
        
        .search-meta .accent {
            color: var(--accent);
        }
        
        /* ─────────────────────────────────────────────────────────────
           METRICS GRID - OPERATIONAL DASHBOARD
           ───────────────────────────────────────────────────────────── */
        
        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 1px;
            background: var(--border-dim);
            border: 1px solid var(--border-subtle);
            margin-bottom: var(--space-xl);
        }
        
        .dashboard-grid.hidden { display: none; }
        
        .metric-section-header {
            grid-column: 1 / -1;
            background: var(--bg-element);
            padding: var(--space-sm) var(--space-md);
            font-size: 10px;
            font-weight: 700;
            letter-spacing: 0.2em;
            color: var(--text-tertiary);
            text-transform: uppercase;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        
        .metric-section-header .section-code {
            color: var(--text-dim);
            font-weight: 400;
        }
        
        .metric-card {
            background: var(--bg-panel);
            padding: var(--space-lg);
            display: flex;
            flex-direction: column;
            gap: var(--space-xs);
            position: relative;
        }
        
        .metric-card::before {
            content: "";
            position: absolute;
            top: 0;
            left: 0;
            width: 3px;
            height: 100%;
            background: var(--border-subtle);
        }
        
        .metric-card.nominal::before { background: var(--state-nominal); }
        .metric-card.caution::before { background: var(--state-caution); }
        .metric-card.warning::before { background: var(--state-warning); }
        .metric-card.critical::before { background: var(--state-critical); }
        
        .metric-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
        }
        
        .metric-label {
            font-size: 10px;
            font-weight: 600;
            letter-spacing: 0.15em;
            color: var(--text-tertiary);
            text-transform: uppercase;
        }
        
        .metric-code {
            font-size: 9px;
            color: var(--text-dim);
            letter-spacing: 0.1em;
        }
        
        .metric-value {
            font-size: 32px;
            font-weight: 700;
            color: var(--text-bright);
            font-variant-numeric: tabular-nums;
            line-height: 1;
            margin: var(--space-sm) 0;
        }
        
        .metric-card.nominal .metric-value { color: var(--state-nominal); }
        .metric-card.critical .metric-value { color: var(--state-critical); }
        .metric-card.warning .metric-value { color: var(--state-warning); }
        
        .metric-footer {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-top: var(--space-sm);
            border-top: 1px dashed var(--border-dim);
        }
        
        .metric-sub {
            font-size: 10px;
            color: var(--text-dim);
            letter-spacing: 0.05em;
        }
        
        .metric-indicator {
            display: flex;
            gap: 2px;
        }
        
        .metric-indicator .bar {
            width: 3px;
            height: 12px;
            background: var(--border-dim);
        }
        
        .metric-indicator .bar.active { background: var(--accent); }
        .metric-indicator .bar.warn { background: var(--state-warning); }
        .metric-indicator .bar.crit { background: var(--state-critical); }
        
        /* Span two columns */
        .metric-wide {
            grid-column: span 2;
        }
        
        /* ─────────────────────────────────────────────────────────────
           SECONDARY METRICS ROW
           ───────────────────────────────────────────────────────────── */
        
        .metrics-secondary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
            gap: 1px;
            background: var(--border-dim);
            border: 1px solid var(--border-subtle);
            margin-bottom: var(--space-xl);
        }
        
        .metrics-secondary.hidden { display: none; }
        
        .metric-mini {
            background: var(--bg-panel);
            padding: var(--space-md);
            text-align: center;
        }
        
        .metric-mini .label {
            font-size: 9px;
            font-weight: 600;
            letter-spacing: 0.15em;
            color: var(--text-dim);
            text-transform: uppercase;
            margin-bottom: var(--space-xs);
        }
        
        .metric-mini .value {
            font-size: 18px;
            font-weight: 700;
            color: var(--text-secondary);
            font-variant-numeric: tabular-nums;
        }

        .metric-rate {
            margin-top: 4px;
            font-size: 9px;
            color: var(--text-tertiary);
            letter-spacing: 0.06em;
            min-height: 1em;
        }

        .sparkline {
            margin-top: 4px;
            font-size: 11px;
            color: var(--text-tertiary);
            font-family: var(--font-mono);
            letter-spacing: 1px;
            min-height: 1em;
        }
        
        .metric-mini.error .value { color: var(--state-critical); }
        .metric-mini.warn .value { color: var(--state-warning); }
        
        /* ─────────────────────────────────────────────────────────────
           RESULTS CONTAINER
           ───────────────────────────────────────────────────────────── */
        
        .results-container {
            display: none;
        }
        
        .results-container.active {
            display: block;
        }
        
        .results-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: var(--space-md);
            padding: var(--space-md);
            background: var(--bg-element);
            border: 1px solid var(--border-subtle);
            border-bottom: none;
        }

        .results-header-main {
            display: flex;
            flex-direction: column;
            gap: var(--space-sm);
            min-width: 0;
        }
        
        .results-title {
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.2em;
            color: var(--text-tertiary);
            text-transform: uppercase;
            display: flex;
            align-items: center;
            flex-wrap: wrap;
            gap: var(--space-md);
        }

        .results-intent {
            font-size: 10px;
            color: var(--accent);
            letter-spacing: 0.1em;
            border: 1px solid rgba(0, 255, 136, 0.4);
            padding: 2px 6px;
            background: rgba(0, 255, 136, 0.1);
        }

        .results-hint {
            font-size: 10px;
            color: var(--text-dim);
            letter-spacing: 0.08em;
            text-transform: none;
        }
        
        .results-count {
            background: var(--accent);
            color: var(--bg-void);
            padding: 2px 8px;
            font-size: 10px;
            font-weight: 700;
        }

        .results-total {
            font-size: 10px;
            color: var(--text-dim);
            letter-spacing: 0.1em;
        }

        .results-meta {
            font-size: 10px;
            color: var(--text-dim);
            letter-spacing: 0.1em;
            display: flex;
            gap: var(--space-lg);
            flex-wrap: wrap;
        }

        .results-tools {
            display: flex;
            flex-direction: column;
            gap: var(--space-sm);
            align-items: flex-end;
        }

        .sort-controls {
            display: flex;
            align-items: center;
            gap: var(--space-sm);
            font-size: 10px;
            color: var(--text-dim);
            letter-spacing: 0.1em;
            text-transform: uppercase;
        }

        .sort-controls select {
            background: var(--bg-panel);
            color: var(--text-secondary);
            border: 1px solid var(--border-subtle);
            font-family: var(--font-mono);
            font-size: 11px;
            padding: 4px 8px;
        }

        .sort-controls select:focus {
            outline: none;
            border-color: var(--accent);
        }

        .compare-tray {
            display: flex;
            align-items: center;
            gap: var(--space-sm);
            font-size: 10px;
            color: var(--text-dim);
            flex-wrap: wrap;
            justify-content: flex-end;
        }

        .compare-tray .compare-title {
            color: var(--accent);
            letter-spacing: 0.1em;
            text-transform: uppercase;
        }

        .compare-tray .compare-keys {
            max-width: 320px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        
        .results-list {
            border: 1px solid var(--border-subtle);
            background: var(--bg-panel);
        }
        
        .result-item {
            display: grid;
            grid-template-columns: auto 1fr auto;
            gap: var(--space-lg);
            padding: var(--space-lg);
            border-bottom: 1px solid var(--border-dim);
            transition: background 0.1s;
            position: relative;
        }
        
        .result-item:last-child {
            border-bottom: none;
        }
        
        .result-item:hover {
            background: var(--bg-element);
        }

        .result-item.selected {
            background: rgba(0, 255, 136, 0.07);
            box-shadow: inset 3px 0 0 var(--accent);
        }
        
        .result-index {
            font-size: 10px;
            font-weight: 700;
            color: var(--text-dim);
            padding: var(--space-xs) var(--space-sm);
            background: var(--bg-base);
            border: 1px solid var(--border-dim);
            height: fit-content;
            min-width: 36px;
            text-align: center;
        }
        
        .result-main {
            display: flex;
            flex-direction: column;
            gap: var(--space-sm);
            min-width: 0;
        }
        
        .result-func {
            font-size: 14px;
            font-weight: 600;
            color: var(--accent);
            word-break: break-all;
            line-height: 1.4;
        }
        
        .result-key {
            font-size: 11px;
            color: var(--text-dim);
            font-family: var(--font-mono);
            display: flex;
            align-items: center;
            gap: var(--space-sm);
        }

        .result-key-copy {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 3px 6px;
            border: 1px solid transparent;
            cursor: copy;
            transition: background 120ms ease, border-color 120ms ease, color 120ms ease;
        }

        .result-key-copy:hover,
        .result-key-copy.copied {
            background: rgba(0, 255, 136, 0.08);
            border-color: rgba(0, 255, 136, 0.35);
            color: var(--accent);
        }

        .result-key-copy::after {
            content: "click to copy";
            font-size: 9px;
            letter-spacing: 0.08em;
            color: var(--text-tertiary);
            text-transform: uppercase;
        }

        .result-key-copy.copied::after {
            content: "copied";
            color: var(--accent);
        }

        .result-age {
            color: var(--text-tertiary);
            font-size: 10px;
            letter-spacing: 0.08em;
        }
        
        .result-mangled {
            font-size: 10px;
            color: var(--text-tertiary);
            font-family: var(--font-mono);
            word-break: break-all;
            line-height: 1.3;
            margin-top: 2px;
            padding: 4px 6px;
            background: rgba(0, 0, 0, 0.3);
            border-left: 2px solid var(--text-tertiary);
            max-height: 40px;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        
        .result-mangled:hover {
            max-height: none;
            background: rgba(0, 0, 0, 0.5);
        }
        
        .lang-badge {
            font-size: 9px;
            font-weight: 700;
            color: var(--bg-void);
            background: var(--state-info);
            padding: 2px 6px;
            letter-spacing: 0.1em;
        }
        
        .result-bins {
            display: flex;
            flex-wrap: wrap;
            gap: var(--space-xs);
            margin-top: var(--space-xs);
        }
        
        .bin-tag {
            font-size: 10px;
            color: var(--state-info);
            background: rgba(0, 136, 255, 0.1);
            border: 1px solid rgba(0, 136, 255, 0.2);
            padding: 2px 8px;
            letter-spacing: 0.05em;
        }
        
        .result-meta {
            display: flex;
            flex-direction: column;
            align-items: flex-end;
            gap: var(--space-xs);
            text-align: right;
        }

        .score-meter {
            width: 110px;
            height: 5px;
            border: 1px solid var(--border-dim);
            background: var(--bg-base);
            position: relative;
            overflow: hidden;
        }

        .score-meter-fill {
            position: absolute;
            top: 0;
            left: 0;
            bottom: 0;
            background: linear-gradient(90deg, var(--accent-dim), var(--accent));
        }

        .result-actions {
            display: flex;
            gap: 4px;
            flex-wrap: wrap;
            justify-content: flex-end;
        }

        .result-action {
            background: var(--bg-base);
            border: 1px solid var(--border-dim);
            color: var(--text-secondary);
            font-family: var(--font-mono);
            font-size: 9px;
            letter-spacing: 0.08em;
            padding: 2px 6px;
            cursor: pointer;
            text-transform: uppercase;
        }

        .result-action:hover {
            border-color: var(--accent);
            color: var(--accent);
        }

        .result-action.active {
            border-color: var(--accent);
            color: var(--bg-void);
            background: var(--accent);
        }

        .result-preview {
            grid-column: 1 / -1;
            margin-top: var(--space-sm);
            border: 1px solid var(--border-dim);
            background: var(--bg-base);
            padding: var(--space-sm);
            display: none;
        }

        .result-preview.active {
            display: block;
        }

        .result-preview-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 1px;
            background: var(--border-dim);
            border: 1px solid var(--border-subtle);
            margin-bottom: var(--space-sm);
        }

        .result-preview-stat {
            background: var(--bg-panel);
            padding: 6px 8px;
            min-width: 0;
        }

        .result-preview-stat .label {
            font-size: 9px;
            letter-spacing: 0.08em;
            color: var(--text-dim);
            text-transform: uppercase;
        }

        .result-preview-stat .value {
            margin-top: 2px;
            font-size: 11px;
            color: var(--text-secondary);
            font-family: var(--font-mono);
            overflow-wrap: anywhere;
        }

        .result-preview-line {
            font-size: 11px;
            color: var(--text-dim);
            white-space: pre-wrap;
            overflow-wrap: anywhere;
        }

        .result-preview-line .k {
            color: var(--text-tertiary);
            text-transform: uppercase;
            font-size: 9px;
            letter-spacing: 0.08em;
            margin-right: 6px;
        }
        
        .version-badge {
            font-size: 10px;
            font-weight: 700;
            color: var(--bg-void);
            background: var(--accent);
            padding: 2px 8px;
            letter-spacing: 0.1em;
        }

        .version-badge.age {
            background: rgba(0, 255, 136, 0.12);
            color: var(--accent);
            border: 1px solid rgba(0, 255, 136, 0.35);
        }
        
        .score-badge {
            font-size: 10px;
            color: var(--text-dim);
            letter-spacing: 0.05em;
        }
        
        /* ─────────────────────────────────────────────────────────────
           PAGINATION CONTROLS
           ───────────────────────────────────────────────────────────── */

        .pagination {
            display: flex;
            justify-content: center;
            align-items: center;
            gap: var(--space-sm);
            padding: var(--space-lg);
            border-top: 1px solid var(--border-dim);
            background: var(--bg-element);
        }

        .pagination-btn {
            background: var(--bg-panel);
            border: 1px solid var(--border-subtle);
            color: var(--text-secondary);
            padding: var(--space-sm) var(--space-md);
            font-family: var(--font-mono);
            font-size: 11px;
            font-weight: 600;
            letter-spacing: 0.1em;
            cursor: pointer;
            transition: all 0.15s;
        }

        .pagination-btn:hover:not(:disabled) {
            border-color: var(--accent);
            color: var(--accent);
            background: var(--accent-glow);
        }

        .pagination-btn:disabled {
            opacity: 0.3;
            cursor: not-allowed;
        }

        .pagination-info {
            font-size: 11px;
            color: var(--text-dim);
            letter-spacing: 0.1em;
            padding: 0 var(--space-md);
        }

        .pagination-info .accent {
            color: var(--accent);
            font-weight: 600;
        }

        /* ─────────────────────────────────────────────────────────────
           FUNCTION DETAIL MODAL
           ───────────────────────────────────────────────────────────── */

        .modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.85);
            z-index: 10000;
            display: none;
            align-items: center;
            justify-content: center;
            padding: var(--space-lg);
            overflow: hidden;
        }

        .modal-overlay.active {
            display: flex;
        }

        .modal-container {
            background: var(--bg-panel);
            border: 1px solid var(--border-subtle);
            width: min(1040px, calc(100vw - (var(--space-lg) * 2)));
            max-height: min(90vh, calc(100dvh - (var(--space-lg) * 2)));
            overflow: hidden;
            display: flex;
            flex-direction: column;
            position: relative;
            box-shadow: 0 24px 80px rgba(0, 0, 0, 0.5);
        }

        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: var(--space-md);
            padding: var(--space-md) var(--space-lg);
            background: var(--bg-element);
            border-bottom: 1px solid var(--border-subtle);
            flex: 0 0 auto;
        }

        .modal-title {
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.2em;
            color: var(--text-tertiary);
            text-transform: uppercase;
            min-width: 0;
            overflow-wrap: anywhere;
        }

        .modal-close {
            background: transparent;
            border: 1px solid var(--border-subtle);
            color: var(--text-secondary);
            width: 32px;
            height: 32px;
            font-size: 16px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.15s;
        }

        .modal-close:hover {
            border-color: var(--state-critical);
            color: var(--state-critical);
            background: rgba(255, 34, 68, 0.1);
        }

        .modal-body {
            padding: var(--space-lg);
            overflow-y: auto;
            flex: 1;
            min-height: 0;
            overscroll-behavior: contain;
        }

        .detail-layout {
            display: flex;
            flex-direction: column;
            gap: var(--space-md);
        }

        .detail-nav {
            position: sticky;
            top: calc(var(--space-lg) * -1);
            z-index: 5;
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            padding: 10px 0 12px;
            background: linear-gradient(to bottom, rgba(15, 15, 15, 0.98), rgba(15, 15, 15, 0.92));
            border-bottom: 1px solid var(--border-subtle);
            backdrop-filter: blur(8px);
        }

        .detail-nav button {
            background: var(--bg-base);
            border: 1px solid var(--border-dim);
            color: var(--text-secondary);
            font-family: var(--font-mono);
            font-size: 10px;
            letter-spacing: 0.08em;
            padding: 6px 10px;
            text-align: left;
            cursor: pointer;
            text-transform: uppercase;
        }

        .detail-nav button:hover,
        .detail-nav button.active {
            color: var(--accent);
            border-color: rgba(0, 255, 136, 0.35);
            background: rgba(0, 255, 136, 0.08);
        }

        .detail-main {
            min-width: 0;
        }

        .compare-diff {
            display: flex;
            flex-direction: column;
            gap: var(--space-lg);
        }

        .compare-head {
            display: grid;
            grid-template-columns: minmax(0, 1fr) 140px minmax(0, 1fr);
            gap: 1px;
            background: var(--border-dim);
            border: 1px solid var(--border-subtle);
        }

        .compare-head-cell {
            background: var(--bg-panel);
            padding: 10px 12px;
            min-width: 0;
        }

        .compare-head-cell.center {
            text-align: center;
            color: var(--text-dim);
            font-size: 10px;
            letter-spacing: 0.12em;
            text-transform: uppercase;
        }

        .compare-name {
            color: var(--accent);
            font-size: 13px;
            font-weight: 600;
            overflow-wrap: anywhere;
        }

        .compare-key {
            margin-top: 4px;
            color: var(--text-tertiary);
            font-size: 10px;
            overflow-wrap: anywhere;
        }

        .compare-section {
            border: 1px solid var(--border-subtle);
            background: var(--border-dim);
        }

        .compare-section-title {
            background: var(--bg-element);
            color: var(--text-dim);
            padding: 8px 10px;
            font-size: 10px;
            letter-spacing: 0.12em;
            text-transform: uppercase;
        }

        .compare-row {
            display: grid;
            grid-template-columns: minmax(0, 1fr) 140px minmax(0, 1fr);
            gap: 1px;
            background: var(--border-dim);
        }

        .compare-row + .compare-row {
            border-top: 1px solid var(--border-subtle);
        }

        .compare-cell,
        .compare-label {
            background: var(--bg-panel);
            padding: 8px 10px;
            min-width: 0;
        }

        .compare-label {
            text-align: center;
            color: var(--text-dim);
            font-size: 10px;
            letter-spacing: 0.08em;
            text-transform: uppercase;
        }

        .compare-cell {
            color: var(--text-secondary);
            font-family: var(--font-mono);
            font-size: 11px;
            overflow-wrap: anywhere;
            white-space: pre-wrap;
        }

        .compare-cell.diff {
            box-shadow: inset 2px 0 0 rgba(255, 170, 0, 0.9);
            background: rgba(255, 170, 0, 0.07);
        }

        .detail-anchor {
            scroll-margin-top: 14px;
        }

        .health-panel {
            border: 1px solid var(--border-subtle);
            background: var(--bg-panel);
            padding: var(--space-md);
            margin-bottom: var(--space-lg);
        }

        .health-bar {
            height: 10px;
            border: 1px solid var(--border-dim);
            background: var(--bg-base);
            position: relative;
            overflow: hidden;
            margin-top: var(--space-sm);
        }

        .health-bar-fill {
            position: absolute;
            top: 0;
            left: 0;
            bottom: 0;
            background: linear-gradient(90deg, var(--accent-dim), var(--accent));
        }

        .health-meta {
            margin-top: var(--space-sm);
            display: flex;
            justify-content: space-between;
            gap: var(--space-sm);
            flex-wrap: wrap;
            font-size: 10px;
            color: var(--text-dim);
        }

        .health-badge {
            border: 1px solid var(--border-dim);
            background: var(--bg-base);
            padding: 2px 8px;
            font-size: 10px;
            letter-spacing: 0.08em;
            text-transform: uppercase;
        }

        .health-badge.good { color: var(--accent); border-color: rgba(0, 255, 136, 0.4); }
        .health-badge.warn { color: var(--state-warning); border-color: rgba(255, 102, 0, 0.45); }
        .health-badge.bad { color: var(--state-critical); border-color: rgba(255, 34, 68, 0.45); }

        .frame-diagnostics {
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
            margin-bottom: var(--space-md);
        }

        .comment-toolbar {
            display: flex;
            justify-content: space-between;
            gap: var(--space-md);
            flex-wrap: wrap;
            margin-bottom: var(--space-md);
            align-items: center;
        }

        .comment-filters {
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
        }

        .comment-filter-btn {
            background: var(--bg-base);
            border: 1px solid var(--border-dim);
            color: var(--text-secondary);
            font-family: var(--font-mono);
            font-size: 10px;
            padding: 4px 8px;
            cursor: pointer;
            text-transform: uppercase;
        }

        .comment-filter-btn.active {
            color: var(--accent);
            border-color: rgba(0, 255, 136, 0.4);
        }

        .comment-search {
            min-width: min(320px, 100%);
            background: var(--bg-base);
            border: 1px solid var(--border-subtle);
            color: var(--text-primary);
            font-family: var(--font-mono);
            font-size: 11px;
            padding: 8px 10px;
        }

        .comment-search:focus {
            outline: none;
            border-color: var(--accent);
        }

        .comment-chunk.collapsed .comment-lane,
        .comment-chunk.collapsed .comment-scale,
        .comment-chunk.collapsed .comment-list {
            display: none;
        }

        .comment-chunk-head {
            cursor: pointer;
        }

        .detail-section {
            margin-bottom: var(--space-lg);
        }

        .detail-section:last-child {
            margin-bottom: 0;
        }

        .detail-label {
            font-size: 10px;
            font-weight: 600;
            letter-spacing: 0.15em;
            color: var(--text-tertiary);
            text-transform: uppercase;
            margin-bottom: var(--space-sm);
        }

        .detail-value {
            font-size: 13px;
            color: var(--text-primary);
            overflow-wrap: anywhere;
            word-break: normal;
        }

        .detail-value.accent {
            color: var(--accent);
            font-weight: 600;
        }

        .detail-value.mono {
            font-family: var(--font-mono);
            font-size: 12px;
            background: var(--bg-base);
            padding: var(--space-sm) var(--space-md);
            border: 1px solid var(--border-dim);
            overflow-x: auto;
            white-space: pre-wrap;
        }

        .detail-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 1px;
            background: var(--border-dim);
            border: 1px solid var(--border-subtle);
            margin-bottom: var(--space-lg);
        }

        .detail-stat {
            background: var(--bg-panel);
            padding: var(--space-md);
            text-align: center;
        }

        .detail-stat .label {
            font-size: 9px;
            font-weight: 600;
            letter-spacing: 0.15em;
            color: var(--text-dim);
            text-transform: uppercase;
            margin-bottom: var(--space-xs);
        }

        .detail-stat .value {
            font-size: 18px;
            font-weight: 700;
            color: var(--text-secondary);
            font-variant-numeric: tabular-nums;
        }

        .detail-stat.nominal .value {
            color: var(--state-nominal);
        }

        .metadata-section {
            background: var(--bg-base);
            border: 1px solid var(--border-dim);
            margin-top: var(--space-md);
        }

        .metadata-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: var(--space-sm) var(--space-md);
            background: var(--bg-element);
            border-bottom: 1px solid var(--border-dim);
            font-size: 10px;
            font-weight: 600;
            letter-spacing: 0.15em;
            color: var(--text-tertiary);
            text-transform: uppercase;
        }

        .metadata-header .badge {
            background: var(--accent);
            color: var(--bg-void);
            padding: 2px 8px;
            font-size: 9px;
            font-weight: 700;
        }

        .metadata-content {
            padding: var(--space-md);
            overflow: visible;
        }

        .metadata-list {
            display: flex;
            flex-direction: column;
            gap: var(--space-xs);
        }

        .metadata-item {
            display: flex;
            gap: var(--space-md);
            padding: var(--space-xs) var(--space-sm);
            font-size: 11px;
            border-left: 2px solid var(--border-dim);
            min-width: 0;
        }

        .metadata-item:hover {
            background: rgba(0, 255, 136, 0.05);
            border-left-color: var(--accent);
        }

        .metadata-item .name {
            color: var(--accent);
            font-weight: 600;
            min-width: 150px;
            overflow-wrap: anywhere;
            word-break: normal;
        }

        .metadata-item .info {
            color: var(--text-dim);
            overflow-wrap: anywhere;
        }

        .metadata-empty {
            color: var(--text-dim);
            font-size: 11px;
            font-style: italic;
        }

        .frame-viz {
            display: flex;
            flex-direction: column;
            gap: var(--space-md);
        }

        .frame-map {
            background: var(--bg-panel);
            border: 1px solid var(--border-subtle);
            padding: var(--space-sm);
        }

        .frame-map-track {
            position: relative;
            height: 38px;
            border: 1px solid var(--border-dim);
            background:
                repeating-linear-gradient(
                    90deg,
                    rgba(255, 255, 255, 0.02) 0,
                    rgba(255, 255, 255, 0.02) 1px,
                    transparent 1px,
                    transparent 24px
                ),
                var(--bg-base);
            overflow: hidden;
        }

        .frame-segment {
            position: absolute;
            top: 4px;
            bottom: 4px;
            min-width: 2px;
            padding: 0 6px;
            border: 1px solid rgba(0, 255, 136, 0.5);
            background: rgba(0, 255, 136, 0.18);
            display: flex;
            align-items: center;
            overflow: hidden;
        }

        .frame-segment span {
            font-size: 10px;
            color: var(--accent);
            white-space: nowrap;
            text-overflow: ellipsis;
            overflow: hidden;
            max-width: 100%;
        }

        .frame-segment.frame-segment-self {
            border-color: rgba(255, 102, 0, 0.6);
            background: rgba(255, 102, 0, 0.18);
        }

        .frame-segment.frame-segment-self span {
            color: var(--state-warning);
        }

        .frame-map-scale {
            display: flex;
            justify-content: space-between;
            margin-top: var(--space-xs);
            font-family: var(--font-mono);
            font-size: 10px;
            color: var(--text-dim);
        }

        .frame-table-wrap {
            overflow-x: auto;
        }

        .frame-table {
            min-width: 680px;
            border: 1px solid var(--border-subtle);
            background: var(--border-dim);
        }

        .frame-table-head,
        .frame-table-row {
            display: grid;
            grid-template-columns: minmax(160px, 1.1fr) 90px 90px minmax(280px, 2.4fr);
            gap: 1px;
            background: var(--border-dim);
        }

        .frame-table-head > div {
            background: var(--bg-element);
            padding: 8px 10px;
            font-size: 9px;
            letter-spacing: 0.12em;
            text-transform: uppercase;
            color: var(--text-dim);
            font-weight: 700;
        }

        .frame-table-row > div {
            background: var(--bg-panel);
            padding: 8px 10px;
            font-size: 11px;
            min-width: 0;
        }

        .frame-table-row:nth-child(even) > div {
            background: rgba(255, 255, 255, 0.01);
        }

        .frame-member-slot {
            color: var(--text-dim);
            margin-right: var(--space-xs);
            font-family: var(--font-mono);
        }

        .frame-member-name {
            color: var(--accent);
            font-weight: 600;
            overflow-wrap: anywhere;
        }

        .frame-num {
            font-family: var(--font-mono);
            color: var(--text-secondary);
        }

        .frame-member-type {
            font-family: var(--font-mono);
            font-size: 12px;
            color: var(--text-secondary);
            overflow-wrap: anywhere;
        }

        .frame-member-meta {
            margin-top: 6px;
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
        }

        .frame-chip {
            border: 1px solid var(--border-dim);
            padding: 1px 6px;
            font-size: 9px;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            color: var(--text-tertiary);
            background: var(--bg-base);
        }

        .frame-chip.warn {
            border-color: rgba(255, 102, 0, 0.6);
            color: var(--state-warning);
        }

        .frame-note {
            margin-top: 4px;
            font-size: 10px;
            color: var(--text-dim);
            overflow-wrap: anywhere;
        }

        .frame-note.warn {
            color: var(--state-warning);
        }

        .frame-missing {
            color: var(--text-dim);
            font-style: italic;
        }

        .signature-viz {
            display: flex;
            flex-direction: column;
            gap: var(--space-md);
        }

        .signature-cards {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 1px;
            background: var(--border-dim);
            border: 1px solid var(--border-subtle);
        }

        .signature-card {
            background: var(--bg-panel);
            padding: 8px 10px;
            min-width: 0;
        }

        .signature-card .label {
            font-size: 9px;
            font-weight: 700;
            letter-spacing: 0.12em;
            text-transform: uppercase;
            color: var(--text-dim);
            margin-bottom: 4px;
        }

        .signature-card .value {
            font-family: var(--font-mono);
            font-size: 12px;
            color: var(--text-secondary);
            overflow-wrap: anywhere;
        }

        .signature-card .value.accent {
            color: var(--accent);
        }

        .signature-args {
            border: 1px solid var(--border-subtle);
            background: var(--border-dim);
        }

        .signature-arg-row {
            display: grid;
            grid-template-columns: 90px 1fr;
            gap: 1px;
            background: var(--border-dim);
        }

        .signature-arg-row + .signature-arg-row {
            border-top: 1px solid var(--border-subtle);
        }

        .signature-arg-key,
        .signature-arg-val {
            background: var(--bg-panel);
            padding: 8px 10px;
            min-width: 0;
        }

        .signature-arg-key {
            font-size: 9px;
            font-weight: 700;
            letter-spacing: 0.1em;
            text-transform: uppercase;
            color: var(--text-dim);
        }

        .signature-arg-val {
            font-family: var(--font-mono);
            font-size: 12px;
            color: var(--text-secondary);
            overflow-wrap: anywhere;
        }

        .comment-timeline {
            display: flex;
            flex-direction: column;
            gap: var(--space-md);
        }

        .comment-chunk {
            border: 1px solid var(--border-subtle);
            background: var(--bg-panel);
            padding: var(--space-sm);
            display: flex;
            flex-direction: column;
            gap: var(--space-sm);
        }

        .comment-chunk-head {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: var(--space-md);
            font-size: 10px;
            letter-spacing: 0.1em;
            text-transform: uppercase;
            color: var(--text-tertiary);
        }

        .comment-chunk-head .count {
            color: var(--text-dim);
            font-family: var(--font-mono);
            text-transform: none;
            letter-spacing: 0;
        }

        .comment-lane {
            position: relative;
            border: 1px solid var(--border-dim);
            background:
                linear-gradient(to bottom, rgba(255, 255, 255, 0.01), rgba(255, 255, 255, 0.01)),
                repeating-linear-gradient(
                    90deg,
                    rgba(255, 255, 255, 0.02) 0,
                    rgba(255, 255, 255, 0.02) 1px,
                    transparent 1px,
                    transparent 18px
                ),
                var(--bg-base);
            overflow: hidden;
        }

        .comment-marker {
            position: absolute;
            transform: translateX(-50%);
            width: 11px;
            height: 11px;
            border-radius: 50%;
            border: 1px solid rgba(0, 255, 136, 0.8);
            background: rgba(0, 255, 136, 0.3);
            box-shadow: 0 0 0 1px rgba(0, 0, 0, 0.45);
            cursor: pointer;
            transition: transform 120ms ease, background 120ms ease;
            z-index: 2;
        }

        .comment-marker:hover {
            transform: translateX(-50%) scale(1.2);
            background: rgba(0, 255, 136, 0.45);
        }

        .comment-marker.active {
            transform: translateX(-50%) scale(1.3);
            background: rgba(0, 255, 136, 0.62);
            box-shadow: 0 0 0 1px rgba(0, 0, 0, 0.45), 0 0 12px rgba(0, 255, 136, 0.55);
        }

        .comment-marker.repeatable {
            border-color: rgba(255, 102, 0, 0.8);
            background: rgba(255, 102, 0, 0.35);
        }

        .comment-marker.repeatable.active {
            background: rgba(255, 102, 0, 0.65);
            box-shadow: 0 0 0 1px rgba(0, 0, 0, 0.45), 0 0 12px rgba(255, 102, 0, 0.55);
        }

        .comment-scale {
            display: flex;
            justify-content: space-between;
            font-family: var(--font-mono);
            font-size: 10px;
            color: var(--text-dim);
        }

        .comment-list {
            border: 1px solid var(--border-subtle);
            background: var(--border-dim);
        }

        .comment-item {
            display: grid;
            grid-template-columns: 130px 1fr;
            gap: 1px;
            background: var(--border-dim);
            cursor: pointer;
        }

        .comment-item:hover .comment-item-head,
        .comment-item:hover .comment-item-text {
            background: rgba(0, 255, 136, 0.04);
        }

        .comment-item + .comment-item {
            border-top: 1px solid var(--border-subtle);
        }

        .comment-item.active .comment-item-head,
        .comment-item.active .comment-item-text {
            background: rgba(0, 255, 136, 0.08);
            box-shadow: inset 2px 0 0 rgba(0, 255, 136, 0.85);
        }

        .comment-item-head,
        .comment-item-text {
            background: var(--bg-panel);
            padding: 8px 10px;
            min-width: 0;
        }

        .comment-item-head {
            display: flex;
            align-items: center;
            gap: 8px;
            font-family: var(--font-mono);
            font-size: 11px;
            color: var(--text-secondary);
        }

        .comment-kind {
            border: 1px solid rgba(0, 255, 136, 0.5);
            color: var(--accent);
            font-size: 9px;
            font-weight: 700;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            padding: 1px 4px;
            min-width: 32px;
            text-align: center;
            background: rgba(0, 255, 136, 0.12);
        }

        .comment-kind.repeatable {
            border-color: rgba(255, 102, 0, 0.5);
            color: var(--state-warning);
            background: rgba(255, 102, 0, 0.14);
        }

        .comment-item-text {
            font-size: 12px;
            color: var(--text-secondary);
            white-space: pre-wrap;
            overflow-wrap: anywhere;
        }

        .detail-loading {
            display: flex;
            align-items: center;
            justify-content: center;
            padding: var(--space-2xl);
            color: var(--text-dim);
        }

        .result-item.clickable {
            cursor: pointer;
        }

        .result-item.clickable:hover {
            background: var(--bg-elevated);
            border-left: 3px solid var(--accent);
        }

        /* ─────────────────────────────────────────────────────────────
           EMPTY / LOADING STATES
           ───────────────────────────────────────────────────────────── */
        
        .state-message {
            text-align: center;
            padding: var(--space-2xl);
            background: var(--bg-panel);
            border: 1px solid var(--border-subtle);
        }
        
        .state-message .icon {
            font-size: 32px;
            color: var(--text-dim);
            margin-bottom: var(--space-md);
        }
        
        .state-message h3 {
            font-family: var(--font-display);
            font-size: 14px;
            font-weight: 700;
            letter-spacing: 0.1em;
            color: var(--text-secondary);
            text-transform: uppercase;
            margin: 0 0 var(--space-sm) 0;
        }
        
        .state-message p {
            font-size: 12px;
            color: var(--text-dim);
            margin: 0;
        }
        
        /* ─────────────────────────────────────────────────────────────
           FOOTER - SYSTEM TELEMETRY BAR
           ───────────────────────────────────────────────────────────── */
        
        .telemetry-bar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: var(--space-md);
            background: var(--bg-panel);
            border: 1px solid var(--border-subtle);
            margin-top: var(--space-xl);
            font-size: 10px;
            color: var(--text-dim);
            letter-spacing: 0.1em;
        }
        
        .telemetry-left,
        .telemetry-right {
            display: flex;
            gap: var(--space-lg);
        }
        
        .telemetry-item {
            display: flex;
            align-items: center;
            gap: var(--space-xs);
        }
        
        .telemetry-item .dot {
            width: 6px;
            height: 6px;
            border-radius: 50%;
            background: var(--text-dim);
        }
        
        .telemetry-item .dot.active { background: var(--state-nominal); }
        .telemetry-item .dot.warn { background: var(--state-warning); }
        .telemetry-item .dot.error { background: var(--state-critical); }
        
        .telemetry-center {
            color: var(--text-tertiary);
            display: flex;
            flex-direction: column;
            gap: 4px;
            align-items: center;
        }

        .telemetry-rates {
            font-size: 9px;
            color: var(--text-dim);
            letter-spacing: 0.08em;
            white-space: nowrap;
        }

        .proto-mix {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            margin-left: 8px;
            font-size: 9px;
            color: var(--text-dim);
        }

        .proto-donut {
            width: 18px;
            height: 18px;
            border-radius: 50%;
            background: conic-gradient(var(--accent) 0deg, var(--accent) 180deg, rgba(255, 102, 0, 0.8) 180deg, rgba(255, 102, 0, 0.8) 360deg);
            border: 1px solid var(--border-subtle);
            position: relative;
        }

        .proto-donut::after {
            content: "";
            position: absolute;
            inset: 4px;
            border-radius: 50%;
            background: var(--bg-panel);
        }
        
        /* ─────────────────────────────────────────────────────────────
           DECORATIVE ELEMENTS
           ───────────────────────────────────────────────────────────── */
        
        .bracket-wrap {
            display: inline-flex;
            align-items: center;
            gap: var(--space-xs);
        }
        
        .bracket-wrap::before { content: "["; color: var(--text-dim); }
        .bracket-wrap::after { content: "]"; color: var(--text-dim); }
        
        .direction-indicator {
            color: var(--text-dim);
            letter-spacing: -2px;
        }
        
        .divider-line {
            height: 1px;
            background: linear-gradient(90deg, transparent, var(--border-subtle), transparent);
            margin: var(--space-lg) 0;
        }
        
        .dot-sequence {
            display: flex;
            gap: 4px;
        }
        
        .dot-sequence .dot {
            width: 4px;
            height: 4px;
            border-radius: 50%;
            background: var(--border-subtle);
        }
        
        .dot-sequence .dot.active {
            background: var(--accent);
        }
        
        /* ─────────────────────────────────────────────────────────────
           RESPONSIVE ADJUSTMENTS
           ───────────────────────────────────────────────────────────── */
        
        @media (max-width: 1200px) {
            .dashboard-grid {
                grid-template-columns: repeat(2, 1fr);
            }
            .metric-wide {
                grid-column: span 1;
            }
            .metrics-secondary {
                grid-template-columns: repeat(2, 1fr);
            }

            .result-preview-grid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
        }
        
        @media (max-width: 768px) {
            .header-grid {
                grid-template-columns: 1fr;
                gap: var(--space-lg);
                text-align: center;
            }
            .header-left, .header-right {
                align-items: center;
                text-align: center;
            }
            .dashboard-grid,
            .metrics-secondary {
                grid-template-columns: 1fr;
            }
            .metric-wide {
                grid-column: span 1;
            }
            .telemetry-bar {
                flex-direction: column;
                gap: var(--space-md);
            }

            .results-header {
                flex-direction: column;
            }

            .results-tools {
                align-items: flex-start;
                width: 100%;
            }

            .compare-tray {
                justify-content: flex-start;
            }

            .results-hint {
                display: block;
                width: 100%;
            }

            .telemetry-rates {
                white-space: normal;
                text-align: center;
            }

            .proto-mix {
                margin-left: 0;
            }
            .terminal-frame {
                padding: var(--space-md);
            }

            .modal-overlay {
                align-items: stretch;
                padding: var(--space-sm);
            }

            .modal-container {
                width: 100%;
                max-height: calc(100dvh - (var(--space-sm) * 2));
            }

            .modal-header {
                padding: var(--space-md);
            }

            .modal-title {
                font-size: 10px;
                letter-spacing: 0.12em;
            }

            .modal-body {
                padding: var(--space-md);
            }

            .detail-grid {
                grid-template-columns: 1fr;
            }

            .detail-nav {
                position: static;
            }

            .metadata-header {
                align-items: flex-start;
                flex-direction: column;
                gap: var(--space-sm);
            }

            .metadata-item,
            .metadata-item > div:first-child {
                flex-direction: column;
                align-items: flex-start !important;
            }

            .metadata-item .name {
                min-width: 0;
            }

            .frame-map-track {
                height: 34px;
            }

            .frame-table {
                min-width: 560px;
            }

            .signature-cards {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }

            .comment-item {
                grid-template-columns: 1fr;
            }
        }

        @media (max-width: 480px) {
            .result-item {
                grid-template-columns: 1fr;
                gap: var(--space-md);
            }
            .result-index {
                width: fit-content;
            }
            .result-meta {
                flex-direction: row;
                align-items: center;
                justify-content: space-between;
                flex-wrap: wrap;
            }

            .result-actions {
                justify-content: flex-start;
            }

            .result-preview-grid {
                grid-template-columns: 1fr;
            }

            .compare-head,
            .compare-row {
                grid-template-columns: 1fr;
            }

            .modal-close {
                width: 36px;
                height: 36px;
                flex: 0 0 36px;
            }

            .signature-cards {
                grid-template-columns: 1fr;
            }

            .signature-arg-row {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="terminal-frame">
        <!-- Classification Banner -->
        <div class="classification-bar">
            <span>DAZHBOG FUNCTION INDEX TERMINAL</span>
            <span class="doc-code">DOC: DZB-SYS-001-R4 // OPERATIONAL</span>
        </div>
        
        <!-- Main Header Grid -->
        <header class="header-grid">
            <div class="header-left">
                <div class="brand-block">
                    <div class="brand-icon">
                        <div class="ring ring-outer"></div>
                        <div class="ring ring-inner"></div>
                        <div class="core"></div>
                    </div>
                    <div class="brand-text">
                        <div class="brand-name">DAZHBOG</div>
                        <div class="brand-sub">Function Metadata Server</div>
                    </div>
                </div>
                <div class="serial-block">
                    <span><span class="label">NODE ID</span><span id="node-id">DZB-001-ALPHA</span></span>
                    <span><span class="label">VERSION</span><span id="sys-version">v1.0.0</span></span>
                    <span><span class="label">PROTOCOL</span><span>LUMINA/TCP</span></span>
                </div>
            </div>
            
            <div class="header-center">
                <div class="status-ring" id="status-ring">
                    <div class="status-core"></div>
                </div>
                <div class="status-label" id="status-label">OPERATIONAL</div>
            </div>
            
            <div class="header-right">
                <div class="timestamp-block" id="timestamp">00:00:00</div>
                <div class="uptime-block">UPTIME <span id="uptime">0d 0h 0m</span></div>
                <div class="coord-block">
                    <span>LAT 00.0000 // LON 00.0000</span>
                    <span>SECTOR: PRIMARY</span>
                </div>
            </div>
        </header>
        
        <!-- Search Terminal -->
        <section class="search-terminal">
            <div class="search-row">
                <span class="search-prompt">&gt;&gt;&gt;</span>
                <div class="search-input-wrap">
                    <input type="text" id="q" class="search-input" placeholder="ENTER QUERY: function name, binary, or address..." autocomplete="off" spellcheck="false">
                    <span class="search-kbd">LIVE</span>
                </div>
            </div>
            <div class="search-meta">
                <span>MODE: <span class="accent">FULL-TEXT</span></span>
                <span>INDEX: <span class="accent" id="index-status">READY</span></span>
                <span>PER PAGE: <span class="accent">25</span></span>
                <span>PRESS <span class="accent">/</span> TO FOCUS</span>
            </div>
        </section>
        
        <!-- Main Content -->
        <main>
            <!-- Primary Metrics Dashboard -->
            <div id="dashboard" class="dashboard-grid">
                <div class="metric-section-header">
                    <span>DATABASE STATUS</span>
                    <span class="section-code">SEC-000</span>
                </div>
                
                <div class="metric-card nominal">
                    <div class="metric-header">
                        <span class="metric-label">Indexed Functions</span>
                        <span class="metric-code">IDX</span>
                    </div>
                    <div class="metric-value" id="m-indexed">0</div>
                    <div class="metric-footer">
                        <span class="metric-sub">Unique Keys</span>
                        <div class="metric-indicator">
                            <div class="bar active"></div>
                            <div class="bar active"></div>
                            <div class="bar active"></div>
                            <div class="bar active"></div>
                            <div class="bar"></div>
                        </div>
                    </div>
                </div>
                
                <div class="metric-card">
                    <div class="metric-header">
                        <span class="metric-label">Storage Used</span>
                        <span class="metric-code">STO</span>
                    </div>
                    <div class="metric-value" id="m-storage">0 B</div>
                    <div class="metric-footer">
                        <span class="metric-sub">Segment Data</span>
                        <div class="metric-indicator">
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                        </div>
                    </div>
                </div>
                
                <div class="metric-card">
                    <div class="metric-header">
                        <span class="metric-label">Search Docs</span>
                        <span class="metric-code">DOC</span>
                    </div>
                    <div class="metric-value" id="m-searchdocs">0</div>
                    <div class="metric-footer">
                        <span class="metric-sub">Searchable</span>
                        <div class="metric-indicator">
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                        </div>
                    </div>
                </div>
                
                <div class="metric-card">
                    <div class="metric-header">
                        <span class="metric-label">Unique Binaries</span>
                        <span class="metric-code">BIN</span>
                    </div>
                    <div class="metric-value" id="m-binaries">0</div>
                    <div class="metric-footer">
                        <span class="metric-sub">Observed</span>
                        <div class="metric-indicator">
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                        </div>
                    </div>
                </div>
                
                <div class="metric-section-header">
                    <span>TRAFFIC ANALYSIS</span>
                    <span class="section-code">SEC-001</span>
                </div>
                
                <div class="metric-card nominal">
                    <div class="metric-header">
                        <span class="metric-label">Queries Processed</span>
                        <span class="metric-code">QRY</span>
                    </div>
                    <div class="metric-value" id="m-queried">0</div>
                    <div class="metric-footer">
                        <span class="metric-sub">Total Lookups</span>
                        <div class="metric-indicator">
                            <div class="bar active"></div>
                            <div class="bar active"></div>
                            <div class="bar active"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                        </div>
                    </div>
                </div>
                
                <div class="metric-card">
                    <div class="metric-header">
                        <span class="metric-label">Active RPC</span>
                        <span class="metric-code">RPC</span>
                    </div>
                    <div class="metric-value" id="m-rpc">0</div>
                    <div class="metric-footer">
                        <span class="metric-sub">Live Connections</span>
                        <div class="metric-indicator">
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                        </div>
                    </div>
                </div>
                
                <div class="metric-card">
                    <div class="metric-header">
                        <span class="metric-label">Upstream Relay</span>
                        <span class="metric-code">UPS</span>
                    </div>
                    <div class="metric-value" id="m-upstream">0</div>
                    <div class="metric-footer">
                        <span class="metric-sub">Lumina Requests</span>
                        <div class="metric-indicator">
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                        </div>
                    </div>
                </div>
                
                <div class="metric-card">
                    <div class="metric-header">
                        <span class="metric-label">Upstream Fetched</span>
                        <span class="metric-code">FTC</span>
                    </div>
                    <div class="metric-value" id="m-fetched">0</div>
                    <div class="metric-footer">
                        <span class="metric-sub">From Origin</span>
                        <div class="metric-indicator">
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                        </div>
                    </div>
                </div>
                
                <div class="metric-section-header">
                    <span>INDEX OPERATIONS</span>
                    <span class="section-code">SEC-002</span>
                </div>
                
                <div class="metric-card nominal">
                    <div class="metric-header">
                        <span class="metric-label">New Functions</span>
                        <span class="metric-code">NEW</span>
                    </div>
                    <div class="metric-value" id="m-new">0</div>
                    <div class="metric-footer">
                        <span class="metric-sub">Unique Indexed</span>
                        <div class="metric-indicator">
                            <div class="bar active"></div>
                            <div class="bar active"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                        </div>
                    </div>
                </div>
                
                <div class="metric-card">
                    <div class="metric-header">
                        <span class="metric-label">Pull Operations</span>
                        <span class="metric-code">PUL</span>
                    </div>
                    <div class="metric-value" id="m-pulls">0</div>
                    <div class="metric-footer">
                        <span class="metric-sub">Metadata Syncs</span>
                        <div class="metric-indicator">
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                        </div>
                    </div>
                </div>
                
                <div class="metric-card">
                    <div class="metric-header">
                        <span class="metric-label">Push Operations</span>
                        <span class="metric-code">PSH</span>
                    </div>
                    <div class="metric-value" id="m-pushes">0</div>
                    <div class="metric-footer">
                        <span class="metric-sub">Submissions</span>
                        <div class="metric-indicator">
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                        </div>
                    </div>
                </div>
                
                <div class="metric-card">
                    <div class="metric-header">
                        <span class="metric-label">Scoring Batches</span>
                        <span class="metric-code">SCR</span>
                    </div>
                    <div class="metric-value" id="m-scoring">0</div>
                    <div class="metric-footer">
                        <span class="metric-sub">Version Selection</span>
                        <div class="metric-indicator">
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Secondary Metrics Row -->
            <div id="metrics-secondary" class="metrics-secondary">
                <div class="metric-mini error">
                    <div class="label">Errors</div>
                    <div class="value" id="m-errors">0</div>
                    <div class="sparkline" id="spark-errors"></div>
                </div>
                <div class="metric-mini warn">
                    <div class="label">Timeouts</div>
                    <div class="value" id="m-timeouts">0</div>
                    <div class="sparkline" id="spark-timeouts"></div>
                </div>
                <div class="metric-mini warn">
                    <div class="label">Decode Rejects</div>
                    <div class="value" id="m-rejects">0</div>
                    <div class="sparkline" id="spark-rejects"></div>
                </div>
                <div class="metric-mini error">
                    <div class="label">Storage Fails</div>
                    <div class="value" id="m-append">0</div>
                    <div class="sparkline" id="spark-append"></div>
                </div>
                <div class="metric-mini warn">
                    <div class="label">Index Overflow</div>
                    <div class="value" id="m-overflow">0</div>
                    <div class="sparkline" id="spark-overflow"></div>
                </div>
                <div class="metric-mini error">
                    <div class="label">Upstream Errors</div>
                    <div class="value" id="m-uperr">0</div>
                    <div class="sparkline" id="spark-uperr"></div>
                </div>
                <div class="metric-mini">
                    <div class="label">Total Records</div>
                    <div class="value" id="m-totalrec">0</div>
                    <div class="metric-rate" id="rate-totalrec"></div>
                </div>
                <div class="metric-mini">
                    <div class="label">Started</div>
                    <div class="value" id="m-start">-</div>
                    <div class="metric-rate" id="rate-start"></div>
                </div>
                <div class="metric-mini">
                    <div class="label">Versions Scored</div>
                    <div class="value" id="m-vconsidered">0</div>
                    <div class="metric-rate" id="rate-vconsidered"></div>
                </div>
                <div class="metric-mini">
                    <div class="label">Fallback Picks</div>
                    <div class="value" id="m-fallback">0</div>
                    <div class="metric-rate" id="rate-fallback"></div>
                </div>
            </div>
            
            <!-- Search Results Container -->
            <div id="results" class="results-container">
                <div class="results-header">
                    <div class="results-header-main">
                        <div class="results-title">
                            <span>QUERY RESULTS</span>
                            <span class="results-count" id="results-count">0</span>
                            <span class="results-total" id="results-total-label"></span>
                            <span class="results-intent" id="results-intent">INTENT: -</span>
                            <span class="results-hint" id="results-hint"></span>
                        </div>
                        <div class="results-meta">
                            <span>LATENCY: <span id="results-latency">0ms</span></span>
                            <span>QUERY: "<span id="results-query"></span>"</span>
                        </div>
                    </div>
                    <div class="results-tools">
                        <div class="sort-controls">
                            <label for="results-sort">Sort</label>
                            <select id="results-sort">
                                <option value="score">Score (Default)</option>
                                <option value="name">Name A-Z</option>
                                <option value="binaries">Binaries Count</option>
                                <option value="lang">Language</option>
                                <option value="recent">Most Recent</option>
                            </select>
                        </div>
                        <div class="compare-tray" id="compare-tray">
                            <span class="compare-title">Compare</span>
                            <span class="compare-keys" id="compare-keys">Pick up to 2 results</span>
                            <button class="pagination-btn" id="compare-open" disabled>Open Compare</button>
                            <button class="pagination-btn" id="compare-clear">Clear</button>
                        </div>
                    </div>
                </div>
                <div class="results-list" id="results-list"></div>
                <div class="pagination" id="pagination"></div>
            </div>
        </main>
        
        <!-- Function Detail Modal -->
        <div class="modal-overlay" id="detail-modal">
            <div class="modal-container">
                <div class="modal-header">
                    <span class="modal-title">FUNCTION DETAIL // <span id="modal-key"></span></span>
                    <button class="modal-close" onclick="closeDetailModal()">&times;</button>
                </div>
                <div class="modal-body" id="modal-body">
                    <div class="detail-loading">&gt;&gt;&gt; LOADING...</div>
                </div>
            </div>
        </div>

        <!-- Telemetry Footer -->
        <footer class="telemetry-bar">
            <div class="telemetry-left">
                <div class="telemetry-item">
                    <span class="dot active" id="tel-storage"></span>
                    <span>STORAGE</span>
                </div>
                <div class="telemetry-item">
                    <span class="dot active" id="tel-index"></span>
                    <span>INDEX</span>
                </div>
                <div class="telemetry-item">
                    <span class="dot active" id="tel-network"></span>
                    <span>NETWORK</span>
                </div>
                <div class="telemetry-item">
                    <span class="dot" id="tel-upstream"></span>
                    <span>UPSTREAM</span>
                </div>
            </div>
            <div class="telemetry-center">
                <span id="sys-time"></span>
                <span class="telemetry-rates">QPS <span id="rate-qps">+0.00/s</span> | PULL <span id="rate-pulls">+0.00/s</span> | PUSH <span id="rate-pushes">+0.00/s</span></span>
            </div>
            <div class="telemetry-right">
                <span>PROTOCOL V5+ CLIENTS: <span id="proto-v5">0</span></span>
                <span>LEGACY CLIENTS: <span id="proto-v0">0</span></span>
                <div class="proto-mix">
                    <div class="proto-donut" id="proto-mix-donut"></div>
                    <span id="proto-mix-label">V5 0% / LEG 0%</span>
                </div>
            </div>
        </footer>
    </div>
    
    <script>
        /* ═══════════════════════════════════════════════════════════════
           DAZHBOG TERMINAL INTERFACE - AXIOM CONTROL SYSTEM
           Document: DZB-JS-001 // Classification: OPERATIONAL
           ═══════════════════════════════════════════════════════════════ */

        const el = {
            q: document.getElementById('q'),
            indexStatus: document.getElementById('index-status'),
            dashboard: document.getElementById('dashboard'),
            secondary: document.getElementById('metrics-secondary'),
            results: document.getElementById('results'),
            resultsList: document.getElementById('results-list'),
            resultsCount: document.getElementById('results-count'),
            resultsTotalLabel: document.getElementById('results-total-label'),
            resultsLatency: document.getElementById('results-latency'),
            resultsQuery: document.getElementById('results-query'),
            resultsIntent: document.getElementById('results-intent'),
            resultsHint: document.getElementById('results-hint'),
            resultsSort: document.getElementById('results-sort'),
            compareTray: document.getElementById('compare-tray'),
            compareKeys: document.getElementById('compare-keys'),
            compareOpen: document.getElementById('compare-open'),
            compareClear: document.getElementById('compare-clear'),
            pagination: document.getElementById('pagination'),
            statusRing: document.getElementById('status-ring'),
            statusLabel: document.getElementById('status-label'),
            timestamp: document.getElementById('timestamp'),
            uptime: document.getElementById('uptime'),
            sysTime: document.getElementById('sys-time'),
            mIndexed: document.getElementById('m-indexed'),
            mStorage: document.getElementById('m-storage'),
            mSearchDocs: document.getElementById('m-searchdocs'),
            mBinaries: document.getElementById('m-binaries'),
            mQueried: document.getElementById('m-queried'),
            mRpc: document.getElementById('m-rpc'),
            mUpstream: document.getElementById('m-upstream'),
            mFetched: document.getElementById('m-fetched'),
            mNew: document.getElementById('m-new'),
            mPulls: document.getElementById('m-pulls'),
            mPushes: document.getElementById('m-pushes'),
            mScoring: document.getElementById('m-scoring'),
            mErrors: document.getElementById('m-errors'),
            mTimeouts: document.getElementById('m-timeouts'),
            mRejects: document.getElementById('m-rejects'),
            mAppend: document.getElementById('m-append'),
            mOverflow: document.getElementById('m-overflow'),
            mUpErr: document.getElementById('m-uperr'),
            mTotalRec: document.getElementById('m-totalrec'),
            mStart: document.getElementById('m-start'),
            mVconsidered: document.getElementById('m-vconsidered'),
            mFallback: document.getElementById('m-fallback'),
            rateTotalRec: document.getElementById('rate-totalrec'),
            rateStart: document.getElementById('rate-start'),
            rateVconsidered: document.getElementById('rate-vconsidered'),
            rateFallback: document.getElementById('rate-fallback'),
            sparkErrors: document.getElementById('spark-errors'),
            sparkTimeouts: document.getElementById('spark-timeouts'),
            sparkRejects: document.getElementById('spark-rejects'),
            sparkAppend: document.getElementById('spark-append'),
            sparkOverflow: document.getElementById('spark-overflow'),
            sparkUpErr: document.getElementById('spark-uperr'),
            telStorage: document.getElementById('tel-storage'),
            telIndex: document.getElementById('tel-index'),
            telNetwork: document.getElementById('tel-network'),
            telUpstream: document.getElementById('tel-upstream'),
            protoV5: document.getElementById('proto-v5'),
            protoV0: document.getElementById('proto-v0'),
            rateQps: document.getElementById('rate-qps'),
            ratePulls: document.getElementById('rate-pulls'),
            ratePushes: document.getElementById('rate-pushes'),
            protoMixDonut: document.getElementById('proto-mix-donut'),
            protoMixLabel: document.getElementById('proto-mix-label'),
            detailModal: document.getElementById('detail-modal'),
            modalKey: document.getElementById('modal-key'),
            modalBody: document.getElementById('modal-body'),
        };

        let searchDebounceTimer = null;
        const DEBOUNCE_MS = 300;
        let currentPage = 1;
        let currentQuery = '';
        let currentHits = [];
        let currentTotalPages = 0;
        let currentPerPage = 25;
        let currentTotal = 0;
        let currentSort = 'score';
        let selectedResultIndex = -1;
        let openPreviewKey = null;

        const pinnedKeys = new Set();
        const compareKeys = [];
        const resultPreviewCache = new Map();

        let metricsPrevSnapshot = null;
        let metricsPrevTsMs = 0;
        const METRIC_SPARK_LIMIT = 24;
        const metricSparkHistory = {
            errors: [],
            timeouts: [],
            rejects: [],
            append: [],
            overflow: [],
            upstream: [],
        };
        const metricPeaks = {};

        let commentFilterKind = 'all';
        let commentSearchTerm = '';
        const collapsedCommentChunks = new Set();

        const fmt = n => Number(n).toLocaleString();
        const fmtBytes = b => {
            if (b === 0) return '0 B';
            const k = 1024, sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(b) / Math.log(k));
            return parseFloat((b / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        };
        const fmtUptime = secs => {
            const d = Math.floor(secs / 86400), h = Math.floor((secs % 86400) / 3600), m = Math.floor((secs % 3600) / 60);
            return `${d}d ${h}h ${m}m`;
        };
        const fmtHex = v => '0x' + Number(v || 0).toString(16);
        const esc = s => (s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

        function fmtRelativeTs(tsSec) {
            const ts = Number(tsSec || 0);
            if (!ts) return 'unknown';
            const now = Math.floor(Date.now() / 1000);
            const delta = Math.max(0, now - ts);
            if (delta < 60) return `${delta}s ago`;
            if (delta < 3600) return `${Math.floor(delta / 60)}m ago`;
            if (delta < 86400) return `${Math.floor(delta / 3600)}h ago`;
            return `${Math.floor(delta / 86400)}d ago`;
        }

        function fmtStartTime(tsSec) {
            const ts = Number(tsSec || 0);
            if (!ts) return '-';
            const d = new Date(ts * 1000);
            return d.toISOString().replace('T', ' ').slice(0, 19) + 'Z';
        }

        function detectQueryIntent(query) {
            const q = (query || '').trim();
            if (!q) return { label: 'INTENT: NONE', hint: '' };

            if (/^(0x)?[0-9a-f]{8,32}$/i.test(q)) {
                return {
                    label: 'INTENT: KEY/ADDR',
                    hint: 'Exact key/address pattern detected. Prefix scores may flatten.',
                };
            }
            if (q.includes('::') || /^_Z/.test(q) || /[<>]/.test(q)) {
                return {
                    label: 'INTENT: SYMBOL',
                    hint: 'Namespace or mangled symbol style query.',
                };
            }
            if (/[\\/]/.test(q) || /\.(exe|dll|so|dylib|bin)$/i.test(q)) {
                return {
                    label: 'INTENT: BINARY',
                    hint: 'Binary/path style query. Binary-name hits should rank strongly.',
                };
            }
            if (/\s/.test(q)) {
                return {
                    label: 'INTENT: MIXED',
                    hint: 'Multi-token query; score can favor broad lexical overlap.',
                };
            }

            return {
                label: 'INTENT: IDENTIFIER',
                hint: 'Single-token identifier search.',
            };
        }

        function estimateMetricMax(name, value) {
            const v = Number(value || 0);
            const prevPeak = metricPeaks[name] || 0;
            metricPeaks[name] = Math.max(prevPeak * 0.97, v, 1);
            return metricPeaks[name];
        }

        function setMetricIndicator(valueElement, rawValue, severity = 'normal') {
            if (!valueElement) return;
            const card = valueElement.closest('.metric-card');
            if (!card) return;
            const bars = card.querySelectorAll('.metric-indicator .bar');
            if (!bars.length) return;

            const max = estimateMetricMax(valueElement.id, rawValue);
            const ratio = Math.max(0, Math.min(1, Number(rawValue || 0) / max));
            const active = Math.max(1, Math.round(ratio * bars.length));

            bars.forEach((bar, i) => {
                bar.className = 'bar';
                if (i < active) {
                    if (severity === 'critical') bar.classList.add('crit');
                    else if (severity === 'warn') bar.classList.add('warn');
                    else bar.classList.add('active');
                }
            });
        }

        function pushSparklinePoint(key, value) {
            const arr = metricSparkHistory[key];
            if (!arr) return;
            arr.push(Number(value || 0));
            while (arr.length > METRIC_SPARK_LIMIT) arr.shift();
        }

        function toSparkline(arr) {
            if (!arr || arr.length === 0) return '';
            const chars = '▁▂▃▄▅▆▇█';
            const min = Math.min(...arr);
            const max = Math.max(...arr);
            const span = Math.max(1, max - min);
            return arr
                .map(v => {
                    const idx = Math.max(0, Math.min(chars.length - 1, Math.round(((v - min) / span) * (chars.length - 1))));
                    return chars[idx];
                })
                .join('');
        }

        function setRateText(elNode, curr, prev, dtSec, suffix = '/s') {
            if (!elNode) return;
            if (!prev || dtSec <= 0) {
                elNode.textContent = '+0.00' + suffix;
                return;
            }
            const rate = (Number(curr || 0) - Number(prev || 0)) / dtSec;
            const sign = rate >= 0 ? '+' : '';
            elNode.textContent = sign + rate.toFixed(2) + suffix;
        }

        function compareTextForKeys() {
            if (compareKeys.length === 0) return 'Pick up to 2 results';
            return compareKeys.join(' vs ');
        }

        function sortHits(hits, mode) {
            const out = [...hits];
            switch (mode) {
                case 'name':
                    out.sort((a, b) => (a.func_name_demangled || a.func_name).localeCompare(b.func_name_demangled || b.func_name));
                    break;
                case 'binaries':
                    out.sort((a, b) => (b.binary_names || []).length - (a.binary_names || []).length || b.score - a.score);
                    break;
                case 'lang':
                    out.sort((a, b) => (a.lang || 'zz').localeCompare(b.lang || 'zz') || b.score - a.score);
                    break;
                case 'recent':
                    out.sort((a, b) => Number(b.ts || 0) - Number(a.ts || 0) || b.score - a.score);
                    break;
                case 'score':
                default:
                    out.sort((a, b) => b.score - a.score);
                    break;
            }

            // Pinning always wins over current sort
            out.sort((a, b) => {
                const ap = pinnedKeys.has(a.key_hex) ? 1 : 0;
                const bp = pinnedKeys.has(b.key_hex) ? 1 : 0;
                return bp - ap;
            });
            return out;
        }

        function setResultsIntent(query) {
            const intent = detectQueryIntent(query);
            el.resultsIntent.textContent = intent.label;
            el.resultsHint.textContent = intent.hint;
        }

        function normalizeScore(score, minScore, maxScore) {
            if (maxScore <= minScore) return 1;
            return Math.max(0, Math.min(1, (score - minScore) / (maxScore - minScore)));
        }

        function copyText(value) {
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(value).catch(() => {});
            }
        }

        function copyResultKey(keyHex) {
            copyText(keyHex);
            copiedKeyHex = keyHex;
            if (copiedKeyTimer) clearTimeout(copiedKeyTimer);
            renderResultsList();
            copiedKeyTimer = setTimeout(() => {
                copiedKeyHex = null;
                copiedKeyTimer = null;
                renderResultsList();
            }, 1200);
        }

        function updateCompareTray() {
            el.compareKeys.textContent = compareTextForKeys();
            el.compareOpen.disabled = compareKeys.length !== 2;
        }

        function togglePin(keyHex) {
            if (pinnedKeys.has(keyHex)) pinnedKeys.delete(keyHex);
            else pinnedKeys.add(keyHex);
            renderResultsList();
        }

        function toggleCompareKey(keyHex) {
            const idx = compareKeys.indexOf(keyHex);
            if (idx >= 0) {
                compareKeys.splice(idx, 1);
            } else {
                if (compareKeys.length >= 2) compareKeys.shift();
                compareKeys.push(keyHex);
            }
            updateCompareTray();
            renderResultsList();
        }

        function clearCompareKeys() {
            compareKeys.length = 0;
            updateCompareTray();
            renderResultsList();
        }

        function openCompareModal() {
            if (compareKeys.length !== 2) return;
            const [a, b] = compareKeys;
            currentDetailData = null;
            el.modalKey.textContent = a + ' // ' + b;
            el.modalBody.innerHTML = '<div class="detail-loading">&gt;&gt;&gt; LOADING COMPARISON...</div>';
            el.detailModal.classList.add('active');
            document.body.style.overflow = 'hidden';

            Promise.all(compareKeys.map(k => fetch('/api/function/' + encodeURIComponent(k)).then(r => r.json())))
                .then(([left, right]) => {
                    el.modalBody.innerHTML = buildStructuredDiff(left, right);
                })
                .catch(err => {
                    el.modalBody.innerHTML = '<div class="state-message"><div class="icon">!</div><h3>COMPARE ERROR</h3><p>' + esc(err.message || String(err)) + '</p></div>';
                });
        }

        function summaryFromMetadata(data) {
            const m = data && data.metadata ? data.metadata : null;
            return {
                typeDecl: m && m.type_parts && m.type_parts.declaration ? m.type_parts.declaration : '-',
                frameMembers: m && m.frame_desc && m.frame_desc.members ? m.frame_desc.members.length : 0,
                comments: m ? ((m.insn_cmts || []).length + (m.rpt_insn_cmts || []).length) : 0,
                parseState: m && m.errors && m.errors.length > 0 ? 'partial' : 'parsed',
                parseErrors: m && m.errors ? m.errors.length : 0,
                vdElapsed: m && m.vd_elapsed !== null && m.vd_elapsed !== undefined ? m.vd_elapsed : null,
                binaries: data && data.binary_names ? data.binary_names.length : 0,
                fcmt: m && m.fcmt ? m.fcmt : null,
                frptcmt: m && m.frptcmt ? m.frptcmt : null,
            };
        }

        function togglePreview(keyHex) {
            openPreviewKey = openPreviewKey === keyHex ? null : keyHex;
            renderResultsList();
            if (openPreviewKey && !resultPreviewCache.has(keyHex)) {
                fetch('/api/function/' + encodeURIComponent(keyHex))
                    .then(r => r.json())
                    .then(data => {
                        resultPreviewCache.set(keyHex, data);
                        if (openPreviewKey === keyHex) renderResultsList();
                    })
                    .catch(() => {
                        resultPreviewCache.set(keyHex, { error: 'preview unavailable' });
                        if (openPreviewKey === keyHex) renderResultsList();
                    });
            }
        }

        function previewHtmlForKey(keyHex) {
            const data = resultPreviewCache.get(keyHex);
            if (!data) return '<div class="result-preview-line">Loading preview...</div>';
            if (data.error) return '<div class="result-preview-line">Preview unavailable</div>';
            const s = summaryFromMetadata(data);
            let html = '<div class="result-preview-grid">';
            html += '<div class="result-preview-stat"><div class="label">Data Size</div><div class="value">' + fmtBytes(data.data_size || 0) + '</div></div>';
            html += '<div class="result-preview-stat"><div class="label">Frame Members</div><div class="value">' + s.frameMembers + '</div></div>';
            html += '<div class="result-preview-stat"><div class="label">Comments</div><div class="value">' + s.comments + '</div></div>';
            html += '<div class="result-preview-stat"><div class="label">Parser State</div><div class="value">' + esc(s.parseState) + '</div></div>';
            html += '<div class="result-preview-stat"><div class="label">Parser Errors</div><div class="value">' + s.parseErrors + '</div></div>';
            html += '<div class="result-preview-stat"><div class="label">Binaries</div><div class="value">' + s.binaries + '</div></div>';
            html += '<div class="result-preview-stat"><div class="label">Age</div><div class="value">' + esc(fmtRelativeTs(data.ts)) + '</div></div>';
            html += '</div>';
            html += '<div class="result-preview-line"><span class="k">type</span>' + esc(s.typeDecl) + '</div>';
            if (s.vdElapsed !== null) {
                html += '<div class="result-preview-line"><span class="k">decomp</span>' + esc(String(s.vdElapsed)) + ' seconds</div>';
            }
            if (data.binary_names && data.binary_names.length > 0) {
                html += '<div class="result-preview-line"><span class="k">bins</span>' + esc(data.binary_names.slice(0, 6).join(', ')) + (data.binary_names.length > 6 ? ' ...' : '') + '</div>';
            }
            if (s.fcmt) {
                html += '<div class="result-preview-line"><span class="k">cmt</span>' + esc(s.fcmt.slice(0, 220)) + (s.fcmt.length > 220 ? ' ...' : '') + '</div>';
            }
            if (!s.fcmt && s.frptcmt) {
                html += '<div class="result-preview-line"><span class="k">rpt</span>' + esc(s.frptcmt.slice(0, 220)) + (s.frptcmt.length > 220 ? ' ...' : '') + '</div>';
            }
            return html;
        }

        function jumpToDetailSection(id) {
            const node = document.getElementById(id);
            if (node) node.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }

        function setActiveDetailNav(id) {
            document.querySelectorAll('.detail-nav button').forEach(btn => {
                btn.classList.toggle('active', btn.dataset.target === id);
            });
        }

        function healthBadgeClass(ratio, errorCount) {
            if (errorCount > 0 || ratio < 0.75) return 'bad';
            if (ratio < 0.98) return 'warn';
            return 'good';
        }

        function renderParseHealth(metadata) {
            const raw = Math.max(1, Number(metadata.raw_size || 0));
            const parsed = Math.max(0, Number(metadata.bytes_parsed || 0));
            const ratio = Math.max(0, Math.min(1, parsed / raw));
            const errCount = (metadata.errors || []).length;
            const stateClass = healthBadgeClass(ratio, errCount);
            const stateLabel = stateClass === 'good' ? 'high confidence' : stateClass === 'warn' ? 'partial' : 'degraded';
            let html = '<div class="health-panel detail-anchor" id="section-health">';
            html += '<div class="detail-label">Parse Health</div>';
            html += '<div class="health-bar"><div class="health-bar-fill" style="width:' + (ratio * 100).toFixed(1) + '%;"></div></div>';
            html += '<div class="health-meta">';
            html += '<span>' + parsed + ' / ' + raw + ' bytes parsed (' + (ratio * 100).toFixed(1) + '%)</span>';
            html += '<span class="health-badge ' + stateClass + '">' + esc(stateLabel) + '</span>';
            html += '<span class="health-badge ' + (errCount ? 'warn' : 'good') + '">' + errCount + ' parser errors</span>';
            html += '</div></div>';
            return html;
        }

        function analyzeFrame(fd) {
            const diagnostics = [];
            if (!fd || !Array.isArray(fd.members) || fd.members.length === 0) return diagnostics;
            const members = [...fd.members]
                .filter(m => m.offset !== null && m.offset !== undefined)
                .sort((a, b) => Number(a.offset) - Number(b.offset));

            for (let i = 0; i < members.length; i++) {
                const cur = members[i];
                const curOff = Number(cur.offset || 0);
                const curSize = Math.max(1, Number(cur.nbytes || 0));
                if (!cur.nbytes) diagnostics.push({ label: 'missing size', kind: 'warn' });
                if (curOff + curSize > Number(fd.frsize || 0) && Number(fd.frsize || 0) > 0) diagnostics.push({ label: 'out of frame', kind: 'warn' });
                if (i > 0) {
                    const prev = members[i - 1];
                    const prevEnd = Number(prev.offset || 0) + Math.max(1, Number(prev.nbytes || 0));
                    if (curOff < prevEnd) diagnostics.push({ label: 'overlap', kind: 'warn' });
                    if (curOff > prevEnd) diagnostics.push({ label: 'gap', kind: 'normal' });
                }
            }
            return diagnostics;
        }

        function renderFrameDiagnostics(fd) {
            const diagnostics = analyzeFrame(fd);
            if (diagnostics.length === 0) {
                return '<div class="frame-diagnostics"><span class="frame-chip">layout coherent</span></div>';
            }
            return '<div class="frame-diagnostics">' + diagnostics.map(d => '<span class="frame-chip' + (d.kind === 'warn' ? ' warn' : '') + '">' + esc(d.label) + '</span>').join('') + '</div>';
        }

        function compareValue(a, b) {
            return String(a || '') !== String(b || '');
        }

        function compareRow(label, left, right) {
            const diff = compareValue(left, right);
            return '<div class="compare-row">'
                + '<div class="compare-cell' + (diff ? ' diff' : '') + '">' + esc(String(left || '-')) + '</div>'
                + '<div class="compare-label">' + esc(label) + '</div>'
                + '<div class="compare-cell' + (diff ? ' diff' : '') + '">' + esc(String(right || '-')) + '</div>'
                + '</div>';
        }

        function renderCompareSection(title, rows) {
            return '<div class="compare-section"><div class="compare-section-title">' + esc(title) + '</div>' + rows.join('') + '</div>';
        }

        function buildStructuredDiff(left, right) {
            const l = summaryFromMetadata(left);
            const r = summaryFromMetadata(right);
            const lm = left.metadata || {};
            const rm = right.metadata || {};
            const leftFrameDiag = analyzeFrame(lm.frame_desc || {});
            const rightFrameDiag = analyzeFrame(rm.frame_desc || {});

            let html = '<div class="compare-diff">';
            html += '<div class="compare-head">';
            html += '<div class="compare-head-cell"><div class="compare-name">' + esc(left.name) + '</div><div class="compare-key">' + esc(left.key_hex) + '</div></div>';
            html += '<div class="compare-head-cell center">Structured Diff</div>';
            html += '<div class="compare-head-cell"><div class="compare-name">' + esc(right.name) + '</div><div class="compare-key">' + esc(right.key_hex) + '</div></div>';
            html += '</div>';

            html += renderCompareSection('Identity', [
                compareRow('Age', fmtRelativeTs(left.ts), fmtRelativeTs(right.ts)),
                compareRow('Data Size', fmtBytes(left.data_size || 0), fmtBytes(right.data_size || 0)),
                compareRow('Binary Count', String((left.binary_names || []).length), String((right.binary_names || []).length)),
                compareRow('Binaries', (left.binary_names || []).join(', '), (right.binary_names || []).join(', ')),
            ]);

            html += renderCompareSection('Type Signature', [
                compareRow('Declaration', l.typeDecl, r.typeDecl),
                compareRow('Parser State', l.parseState, r.parseState),
                compareRow('Parser Errors', String(l.parseErrors), String(r.parseErrors)),
                compareRow('Decomp Time', l.vdElapsed !== null ? String(l.vdElapsed) + ' sec' : '-', r.vdElapsed !== null ? String(r.vdElapsed) + ' sec' : '-'),
            ]);

            html += renderCompareSection('Frame Layout', [
                compareRow('Members', String(l.frameMembers), String(r.frameMembers)),
                compareRow('Frame Size', fmtHex(lm.frame_desc && lm.frame_desc.frsize), fmtHex(rm.frame_desc && rm.frame_desc.frsize)),
                compareRow('Arg Size', fmtHex(lm.frame_desc && lm.frame_desc.argsize), fmtHex(rm.frame_desc && rm.frame_desc.argsize)),
                compareRow('Diagnostics', leftFrameDiag.map(x => x.label).join(', ') || 'layout coherent', rightFrameDiag.map(x => x.label).join(', ') || 'layout coherent'),
            ]);

            html += renderCompareSection('Comments', [
                compareRow('Instruction Comments', String(l.comments), String(r.comments)),
                compareRow('Regular Comment', l.fcmt || '-', r.fcmt || '-'),
                compareRow('Repeatable Comment', l.frptcmt || '-', r.frptcmt || '-'),
            ]);

            html += renderCompareSection('Parser', [
                compareRow('Bytes Parsed', String(lm.bytes_parsed || 0), String(rm.bytes_parsed || 0)),
                compareRow('Raw Size', fmtBytes(lm.raw_size || 0), fmtBytes(rm.raw_size || 0)),
                compareRow('Error List', (lm.errors || []).join(' | ') || '-', (rm.errors || []).join(' | ') || '-'),
            ]);

            html += '</div>';
            return html;
        }

        function renderFrameDescriptor(fd) {
            const members = Array.isArray(fd.members) ? [...fd.members] : [];
            if (members.length === 0) {
                return '<div class="metadata-empty">No frame members</div>';
            }

            members.sort((a, b) => {
                const ao = (a.offset === null || a.offset === undefined) ? Number.MAX_SAFE_INTEGER : Number(a.offset);
                const bo = (b.offset === null || b.offset === undefined) ? Number.MAX_SAFE_INTEGER : Number(b.offset);
                if (ao !== bo) return ao - bo;
                const as = (a.nbytes === null || a.nbytes === undefined) ? 0 : Number(a.nbytes);
                const bs = (b.nbytes === null || b.nbytes === undefined) ? 0 : Number(b.nbytes);
                return bs - as;
            });

            const frameSize = Number(fd.frsize || 0);
            const derivedSize = members.reduce((max, mem) => {
                const off = (mem.offset === null || mem.offset === undefined) ? 0 : Number(mem.offset);
                const sz = (mem.nbytes === null || mem.nbytes === undefined) ? 1 : Math.max(1, Number(mem.nbytes));
                return Math.max(max, off + sz);
            }, 1);
            const scaleSize = Math.max(frameSize, derivedSize, 1);

            let html = '<div class="frame-viz">';
            html += '<div class="frame-map">';
            html += '<div class="frame-map-track">';

            members.forEach((mem, i) => {
                const hasOffset = mem.offset !== null && mem.offset !== undefined;
                const hasSize = mem.nbytes !== null && mem.nbytes !== undefined;
                const off = hasOffset ? Number(mem.offset) : 0;
                const size = hasSize ? Math.max(1, Number(mem.nbytes)) : 1;

                let leftPct = Math.max(0, Math.min(100, (off / scaleSize) * 100));
                let widthPct = Math.max(1.2, (size / scaleSize) * 100);
                if (leftPct + widthPct > 100) {
                    widthPct = Math.max(1.2, 100 - leftPct);
                }

                const label = mem.name ? mem.name : ('m' + i);
                const isSelf = mem.name && mem.name.toLowerCase() === 'self';
                const tooltip = 'Member ' + i
                    + (mem.name ? ' (' + mem.name + ')' : '')
                    + (hasOffset ? ' | off ' + fmtHex(off) : '')
                    + (hasSize ? ' | size ' + fmtHex(size) : '');

                html += '<div class="frame-segment' + (isSelf ? ' frame-segment-self' : '') + '" style="left:' + leftPct.toFixed(2) + '%;width:' + widthPct.toFixed(2) + '%;" title="' + esc(tooltip) + '">';
                html += '<span>' + esc(label) + '</span>';
                html += '</div>';
            });

            html += '</div>';
            html += '<div class="frame-map-scale"><span>0x0</span><span>' + fmtHex(scaleSize) + '</span></div>';
            html += '</div>';

            html += '<div class="frame-table-wrap"><div class="frame-table">';
            html += '<div class="frame-table-head"><div>Member</div><div>Offset</div><div>Size</div><div>Type / Notes</div></div>';

            members.forEach((mem, i) => {
                const offText = (mem.offset === null || mem.offset === undefined) ? '-' : fmtHex(mem.offset);
                const sizeText = (mem.nbytes === null || mem.nbytes === undefined) ? '-' : fmtHex(mem.nbytes);
                const memberName = mem.name ? esc(mem.name) : 'unnamed';

                let typeHtml = '<span class="frame-missing">no decoded type</span>';
                if (mem.tinfo && mem.tinfo.declaration) {
                    typeHtml = esc(mem.tinfo.declaration);
                }

                const chips = [];
                if (mem.has_info) chips.push('<span class="frame-chip">opinfo</span>');
                if (mem.tinfo && mem.tinfo.decode_error) chips.push('<span class="frame-chip warn">decode issue</span>');

                let notes = '';
                if (chips.length > 0) {
                    notes += '<div class="frame-member-meta">' + chips.join('') + '</div>';
                }
                if (mem.tinfo && mem.tinfo.decode_error) {
                    notes += '<div class="frame-note warn">decode: ' + esc(mem.tinfo.decode_error) + '</div>';
                }
                if (mem.cmt) {
                    notes += '<div class="frame-note">cmt: ' + esc(mem.cmt) + '</div>';
                }
                if (mem.rptcmt) {
                    notes += '<div class="frame-note">rpt: ' + esc(mem.rptcmt) + '</div>';
                }

                html += '<div class="frame-table-row">';
                html += '<div><span class="frame-member-slot">#' + i + '</span><span class="frame-member-name">' + memberName + '</span></div>';
                html += '<div class="frame-num">' + offText + '</div>';
                html += '<div class="frame-num">' + sizeText + '</div>';
                html += '<div><div class="frame-member-type">' + typeHtml + '</div>' + notes + '</div>';
                html += '</div>';
            });

            html += '</div></div>';
            html += '</div>';
            return html;
        }

        function splitTopLevelComma(text) {
            const parts = [];
            let cur = '';
            let paren = 0;
            let square = 0;
            let angle = 0;
            let brace = 0;

            for (let i = 0; i < text.length; i++) {
                const ch = text[i];

                if (ch === '(') paren++;
                else if (ch === ')' && paren > 0) paren--;
                else if (ch === '[') square++;
                else if (ch === ']' && square > 0) square--;
                else if (ch === '<') angle++;
                else if (ch === '>' && angle > 0) angle--;
                else if (ch === '{') brace++;
                else if (ch === '}' && brace > 0) brace--;

                if (ch === ',' && paren === 0 && square === 0 && angle === 0 && brace === 0) {
                    if (cur.trim()) parts.push(cur.trim());
                    cur = '';
                    continue;
                }
                cur += ch;
            }

            if (cur.trim()) parts.push(cur.trim());
            return parts;
        }

        function parseDecodedSignature(declaration) {
            const decl = (declaration || '').trim();
            if (!decl) return null;

            const close = decl.lastIndexOf(')');
            if (close <= 0) return null;

            let depth = 0;
            let open = -1;
            for (let i = close; i >= 0; i--) {
                const ch = decl[i];
                if (ch === ')') depth++;
                else if (ch === '(') {
                    depth--;
                    if (depth === 0) {
                        open = i;
                        break;
                    }
                }
            }
            if (open < 0) return null;

            const head = decl.slice(0, open).trim();
            const argsBlock = decl.slice(open + 1, close).trim();
            if (!head || head.includes('(*')) {
                return null;
            }

            const ccPattern = /__(?:cdecl|stdcall|pascal|fastcall|thiscall|swiftcall|golang|usercall|userpurge|cc\([^)]*\))/;
            const ccMatch = head.match(ccPattern);
            if (!ccMatch || ccMatch.index === undefined) {
                return null;
            }

            let cc = null;
            let returnType = head;
            let tail = '';

            cc = ccMatch[0];
            returnType = head.slice(0, ccMatch.index).trim();
            tail = head.slice(ccMatch.index + cc.length).trim();

            if (!returnType) returnType = head;
            const retLocMatch = tail.match(/@<[^>]+>/);
            const retLoc = retLocMatch ? retLocMatch[0] : null;

            let args = [];
            if (argsBlock.length > 0) {
                args = splitTopLevelComma(argsBlock);
                if (args.length === 1 && args[0] === 'void') {
                    args = [];
                }
            }

            return {
                returnType,
                cc,
                retLoc,
                args,
                full: decl,
            };
        }

        function renderTypeSignature(typeParts) {
            const decl = typeParts && typeParts.declaration ? typeParts.declaration : '';
            const parsed = parseDecodedSignature(decl);

            let html = '<div class="signature-viz">';
            if (parsed) {
                html += '<div class="signature-cards">';
                html += '<div class="signature-card"><div class="label">User Type</div><div class="value accent">' + (typeParts.userti ? 'YES' : 'NO') + '</div></div>';
                html += '<div class="signature-card"><div class="label">Return Type</div><div class="value">' + esc(parsed.returnType || '-') + '</div></div>';
                html += '<div class="signature-card"><div class="label">Calling Conv</div><div class="value">' + esc(parsed.cc || 'default') + '</div></div>';
                html += '<div class="signature-card"><div class="label">Return Loc</div><div class="value">' + esc(parsed.retLoc || '-') + '</div></div>';
                html += '</div>';

                if (parsed.args.length > 0) {
                    html += '<div class="detail-label" style="margin:0;">Arguments</div>';
                    html += '<div class="signature-args">';
                    parsed.args.forEach((arg, i) => {
                        const kind = arg === '...' ? 'vararg' : ('arg ' + i);
                        html += '<div class="signature-arg-row">';
                        html += '<div class="signature-arg-key">' + esc(kind) + '</div>';
                        html += '<div class="signature-arg-val">' + esc(arg) + '</div>';
                        html += '</div>';
                    });
                    html += '</div>';
                } else {
                    html += '<div class="metadata-empty">No explicit arguments</div>';
                }

                html += '<div class="detail-section" style="margin-bottom:0;"><div class="detail-label">Full Declaration</div><div class="detail-value mono">' + esc(parsed.full) + '</div></div>';
            } else {
                html += '<div class="signature-cards">';
                html += '<div class="signature-card"><div class="label">User Type</div><div class="value accent">' + (typeParts.userti ? 'YES' : 'NO') + '</div></div>';
                html += '<div class="signature-card" style="grid-column: span 3;"><div class="label">Decoded Declaration</div><div class="value">' + esc(decl || 'not available') + '</div></div>';
                html += '</div>';
            }

            if (typeParts && typeParts.decode_error) {
                html += '<div class="detail-section" style="margin-bottom:0;"><div class="detail-label">Decode Error</div><div class="detail-value">' + esc(typeParts.decode_error) + '</div></div>';
            }

            html += '</div>';
            return html;
        }

        function renderInstructionCommentTimeline(insnCmts, rptInsnCmts) {
            const events = [];
            if (Array.isArray(insnCmts)) {
                insnCmts.forEach(c => {
                    events.push({
                        kind: 'reg',
                        chunk: Number(c.fchunk_nr || 0),
                        off: Number(c.fchunk_off || 0),
                        cmt: c.cmt || '',
                    });
                });
            }
            if (Array.isArray(rptInsnCmts)) {
                rptInsnCmts.forEach(c => {
                    events.push({
                        kind: 'rpt',
                        chunk: Number(c.fchunk_nr || 0),
                        off: Number(c.fchunk_off || 0),
                        cmt: c.cmt || '',
                    });
                });
            }

            if (events.length === 0) {
                return '<div class="metadata-empty">No instruction comments</div>';
            }

            const filterKind = commentFilterKind;
            const term = commentSearchTerm.trim().toLowerCase();
            const filteredEvents = events.filter(ev => {
                if (filterKind !== 'all' && ev.kind !== filterKind) return false;
                if (term && !ev.cmt.toLowerCase().includes(term)) return false;
                return true;
            });

            let html = '<div class="comment-toolbar">';
            html += '<div class="comment-filters">';
            html += '<button class="comment-filter-btn' + (filterKind === 'all' ? ' active' : '') + '" onclick="setCommentFilter(\'all\')">All</button>';
            html += '<button class="comment-filter-btn' + (filterKind === 'reg' ? ' active' : '') + '" onclick="setCommentFilter(\'reg\')">Regular</button>';
            html += '<button class="comment-filter-btn' + (filterKind === 'rpt' ? ' active' : '') + '" onclick="setCommentFilter(\'rpt\')">Repeatable</button>';
            html += '</div>';
            html += '<input class="comment-search" placeholder="Filter comment text..." value="' + esc(commentSearchTerm) + '" oninput="setCommentSearchTerm(this.value)">';
            html += '</div>';

            if (filteredEvents.length === 0) {
                html += '<div class="metadata-empty">No comments match current filters</div>';
                return html;
            }

            const byChunk = new Map();
            filteredEvents.forEach(ev => {
                if (!byChunk.has(ev.chunk)) byChunk.set(ev.chunk, []);
                byChunk.get(ev.chunk).push(ev);
            });

            const chunks = Array.from(byChunk.entries()).sort((a, b) => a[0] - b[0]);
            html += '<div class="comment-timeline">';

            chunks.forEach(([chunkId, chunkEvents]) => {
                const list = [...chunkEvents].sort((a, b) => {
                    if (a.off !== b.off) return a.off - b.off;
                    return a.kind.localeCompare(b.kind);
                });

                list.forEach((ev, i) => {
                    ev.rowId = 'cmt-' + chunkId + '-' + i;
                    ev.markerId = 'cmtm-' + chunkId + '-' + i;
                });

                const minOff = list[0].off;
                const maxOff = list[list.length - 1].off;
                const span = Math.max(1, maxOff - minOff);

                const atOffsetCount = new Map();
                let maxStack = 0;
                list.forEach(ev => {
                    const key = String(ev.off);
                    const stack = atOffsetCount.get(key) || 0;
                    ev.stack = stack;
                    atOffsetCount.set(key, stack + 1);
                    if (stack > maxStack) maxStack = stack;
                });

                const laneHeight = 24 + (maxStack * 8);
                const collapsed = collapsedCommentChunks.has(chunkId);

                html += '<div class="comment-chunk' + (collapsed ? ' collapsed' : '') + '">';
                html += '<div class="comment-chunk-head" onclick="toggleCommentChunk(' + chunkId + ')"><span>Chunk ' + chunkId + '</span><span class="count">' + list.length + ' comments</span></div>';
                html += '<div class="comment-lane" style="height:' + laneHeight + 'px;">';

                list.forEach(ev => {
                    const left = ((ev.off - minOff) / span) * 100;
                    const top = 6 + (ev.stack * 8);
                    const title = (ev.kind === 'rpt' ? 'Repeatable' : 'Regular') + ' @ ' + fmtHex(ev.off) + ': ' + ev.cmt;
                    html += '<div id="' + ev.markerId + '" class="comment-marker' + (ev.kind === 'rpt' ? ' repeatable' : '') + '" style="left:' + left.toFixed(2) + '%;top:' + top + 'px;" title="' + esc(title) + '" onmouseenter="pulseCommentMarker(\'' + ev.markerId + '\')" onclick="focusCommentRow(\'' + ev.rowId + '\', \'' + ev.markerId + '\', true)"></div>';
                });

                html += '</div>';
                html += '<div class="comment-scale"><span>' + fmtHex(minOff) + '</span><span>' + fmtHex(maxOff) + '</span></div>';

                html += '<div class="comment-list">';
                list.forEach(ev => {
                    html += '<div class="comment-item" id="' + ev.rowId + '" onmouseenter="pulseCommentMarker(\'' + ev.markerId + '\')" onclick="focusCommentRow(\'' + ev.rowId + '\', \'' + ev.markerId + '\', false)">';
                    html += '<div class="comment-item-head">';
                    html += '<span class="comment-kind' + (ev.kind === 'rpt' ? ' repeatable' : '') + '">' + (ev.kind === 'rpt' ? 'RPT' : 'REG') + '</span>';
                    html += '<span>' + fmtHex(ev.off) + '</span>';
                    html += '</div>';
                    html += '<div class="comment-item-text">' + esc(ev.cmt) + '</div>';
                    html += '</div>';
                });
                html += '</div>';
                html += '</div>';
            });

            html += '</div>';
            return html;
        }

        let activeCommentRow = null;
        let activeCommentRowTimer = null;
        let activeCommentMarker = null;
        let activeCommentMarkerTimer = null;
        let currentDetailData = null;
        let copiedKeyHex = null;
        let copiedKeyTimer = null;

        function pulseCommentMarker(markerId) {
            if (!markerId) return;
            const marker = document.getElementById(markerId);
            if (!marker) return;

            if (activeCommentMarker && activeCommentMarker !== marker) {
                activeCommentMarker.classList.remove('active');
            }
            if (activeCommentMarkerTimer) {
                clearTimeout(activeCommentMarkerTimer);
                activeCommentMarkerTimer = null;
            }

            marker.classList.add('active');
            activeCommentMarker = marker;
            activeCommentMarkerTimer = setTimeout(() => {
                marker.classList.remove('active');
                if (activeCommentMarker === marker) {
                    activeCommentMarker = null;
                }
                activeCommentMarkerTimer = null;
            }, 1400);
        }

        function focusCommentRow(rowId, markerId = null, shouldScroll = true) {
            const row = document.getElementById(rowId);
            if (!row) return;

            pulseCommentMarker(markerId);

            if (shouldScroll) {
                row.scrollIntoView({ behavior: 'smooth', block: 'center', inline: 'nearest' });
            }

            if (activeCommentRow && activeCommentRow !== row) {
                activeCommentRow.classList.remove('active');
            }
            if (activeCommentRowTimer) {
                clearTimeout(activeCommentRowTimer);
                activeCommentRowTimer = null;
            }

            row.classList.add('active');
            activeCommentRow = row;
            activeCommentRowTimer = setTimeout(() => {
                row.classList.remove('active');
                if (activeCommentRow === row) {
                    activeCommentRow = null;
                }
                activeCommentRowTimer = null;
            }, 1700);
        }

        function setCommentFilter(kind) {
            commentFilterKind = kind;
            if (currentDetailData) renderFunctionDetail(currentDetailData);
        }

        function setCommentSearchTerm(value) {
            commentSearchTerm = value || '';
            if (currentDetailData) renderFunctionDetail(currentDetailData);
        }

        function toggleCommentChunk(chunkId) {
            if (collapsedCommentChunks.has(chunkId)) collapsedCommentChunks.delete(chunkId);
            else collapsedCommentChunks.add(chunkId);
            if (currentDetailData) renderFunctionDetail(currentDetailData);
        }

        function parseHash() {
            const params = new URLSearchParams(window.location.hash.slice(1));
            return {
                q: params.get('q') || '',
                page: parseInt(params.get('page') || '1', 10) || 1
            };
        }

        function updateHash(query, page = 1) {
            if (query) {
                let hash = 'q=' + encodeURIComponent(query);
                if (page > 1) hash += '&page=' + page;
                window.location.hash = hash;
            } else {
                history.replaceState(null, '', window.location.pathname);
            }
        }

        function updateTime() {
            const now = new Date();
            el.timestamp.textContent = now.toTimeString().split(' ')[0];
            el.sysTime.textContent = `${now.toISOString().split('T')[0]} ${now.toTimeString().split(' ')[0]} UTC`;
        }

        async function fetchMetrics() {
            try {
                const r = await fetch('/api/metrics');
                if (!r.ok) throw new Error(r.status);
                const d = await r.json();

                const nowMs = Date.now();
                const prev = metricsPrevSnapshot;
                const dtSec = metricsPrevTsMs > 0 ? Math.max(0.001, (nowMs - metricsPrevTsMs) / 1000) : 0;

                el.mIndexed.textContent = fmt(d.indexed_funcs || 0);
                el.mStorage.textContent = fmtBytes(d.storage_bytes || 0);
                el.mSearchDocs.textContent = fmt(d.search_docs || 0);
                el.mBinaries.textContent = fmt(d.unique_binaries || 0);
                el.mQueried.textContent = fmt(d.queried_funcs || 0);
                el.mRpc.textContent = fmt(d.active_connections || 0);
                el.mUpstream.textContent = fmt(d.upstream_requests || 0);
                el.mFetched.textContent = fmt(d.upstream_fetched || 0);
                el.mNew.textContent = fmt(d.new_funcs || 0);
                el.mPulls.textContent = fmt(d.pulls || 0);
                el.mPushes.textContent = fmt(d.pushes || 0);
                el.mScoring.textContent = fmt(d.scoring_batches || 0);
                el.mErrors.textContent = fmt(d.errors || 0);
                el.mTimeouts.textContent = fmt(d.timeouts || 0);
                el.mRejects.textContent = fmt(d.decoder_rejects || 0);
                el.mAppend.textContent = fmt(d.append_failures || 0);
                el.mOverflow.textContent = fmt(d.index_overflows || 0);
                el.mUpErr.textContent = fmt(d.upstream_errors || 0);
                el.mTotalRec.textContent = fmt(d.total_records || 0);
                el.mStart.textContent = fmtStartTime(d.start_time || 0);
                el.mVconsidered.textContent = fmt(d.scoring_versions_considered || 0);
                el.mFallback.textContent = fmt(d.scoring_fallback_latest || 0);

                el.protoV5.textContent = fmt(d.lumina_v5p || 0);
                el.protoV0.textContent = fmt(d.lumina_v0_4 || 0);

                setRateText(el.rateQps, d.queried_funcs, prev && prev.queried_funcs, dtSec);
                setRateText(el.ratePulls, d.pulls, prev && prev.pulls, dtSec);
                setRateText(el.ratePushes, d.pushes, prev && prev.pushes, dtSec);
                setRateText(el.rateTotalRec, d.total_records, prev && prev.total_records, dtSec);
                setRateText(el.rateVconsidered, d.scoring_versions_considered, prev && prev.scoring_versions_considered, dtSec);
                setRateText(el.rateFallback, d.scoring_fallback_latest, prev && prev.scoring_fallback_latest, dtSec);
                el.rateStart.textContent = 'uptime ' + fmtUptime(d.uptime_secs || 0);

                pushSparklinePoint('errors', d.errors || 0);
                pushSparklinePoint('timeouts', d.timeouts || 0);
                pushSparklinePoint('rejects', d.decoder_rejects || 0);
                pushSparklinePoint('append', d.append_failures || 0);
                pushSparklinePoint('overflow', d.index_overflows || 0);
                pushSparklinePoint('upstream', d.upstream_errors || 0);
                el.sparkErrors.textContent = toSparkline(metricSparkHistory.errors);
                el.sparkTimeouts.textContent = toSparkline(metricSparkHistory.timeouts);
                el.sparkRejects.textContent = toSparkline(metricSparkHistory.rejects);
                el.sparkAppend.textContent = toSparkline(metricSparkHistory.append);
                el.sparkOverflow.textContent = toSparkline(metricSparkHistory.overflow);
                el.sparkUpErr.textContent = toSparkline(metricSparkHistory.upstream);

                const p5 = Number(d.lumina_v5p || 0);
                const p0 = Number(d.lumina_v0_4 || 0);
                const totalProto = Math.max(1, p5 + p0);
                const p5Pct = (p5 / totalProto) * 100;
                const deg = Math.round((p5Pct / 100) * 360);
                el.protoMixDonut.style.background = 'conic-gradient(var(--accent) 0deg, var(--accent) ' + deg + 'deg, rgba(255, 102, 0, 0.8) ' + deg + 'deg, rgba(255, 102, 0, 0.8) 360deg)';
                el.protoMixLabel.textContent = 'V5 ' + p5Pct.toFixed(1) + '% / LEG ' + (100 - p5Pct).toFixed(1) + '%';

                setMetricIndicator(el.mIndexed, d.indexed_funcs);
                setMetricIndicator(el.mStorage, d.storage_bytes);
                setMetricIndicator(el.mSearchDocs, d.search_docs);
                setMetricIndicator(el.mBinaries, d.unique_binaries);
                setMetricIndicator(el.mQueried, d.queried_funcs);
                setMetricIndicator(el.mRpc, d.active_connections);
                setMetricIndicator(el.mUpstream, d.upstream_requests);
                setMetricIndicator(el.mFetched, d.upstream_fetched);
                setMetricIndicator(el.mNew, d.new_funcs);
                setMetricIndicator(el.mPulls, d.pulls);
                setMetricIndicator(el.mPushes, d.pushes);
                setMetricIndicator(el.mScoring, d.scoring_batches);

                el.statusRing.classList.remove('offline');
                el.statusLabel.classList.remove('offline');
                el.statusLabel.textContent = 'OPERATIONAL';
                el.indexStatus.textContent = 'READY';
                el.telStorage.className = 'dot ' + ((d.append_failures || 0) > 0 ? 'error' : 'active');
                el.telIndex.className = 'dot ' + ((d.index_overflows || 0) > 0 ? 'warn' : 'active');
                el.telNetwork.className = 'dot ' + ((d.errors || 0) > 0 ? 'warn' : 'active');
                el.telUpstream.className = 'dot ' + ((d.upstream_requests || 0) > 0 ? 'active' : '');
                el.uptime.textContent = fmtUptime(d.uptime_secs || 0);

                metricsPrevSnapshot = d;
                metricsPrevTsMs = nowMs;
            } catch (e) {
                el.statusRing.classList.add('offline');
                el.statusLabel.classList.add('offline');
                el.statusLabel.textContent = 'OFFLINE';
                el.indexStatus.textContent = 'ERROR';
            }
        }

        function showDashboard() {
            el.dashboard.classList.remove('hidden');
            el.secondary.classList.remove('hidden');
            el.results.classList.remove('active');
            el.pagination.innerHTML = '';
            currentPage = 1;
            currentQuery = '';
            currentHits = [];
            selectedResultIndex = -1;
            openPreviewKey = null;
            updateHash('');
        }

        async function runSearch(query, page = 1, updateUrl = true) {
            query = query.trim();
            if (!query) { showDashboard(); return; }

            currentQuery = query;
            currentPage = page;

            el.dashboard.classList.add('hidden');
            el.secondary.classList.add('hidden');
            el.results.classList.add('active');
            el.resultsQuery.textContent = query;
            el.resultsList.innerHTML = '<div class="state-message"><div class="icon">&gt;&gt;&gt;</div><h3>QUERYING INDEX</h3><p>Processing request...</p></div>';
            el.pagination.innerHTML = '';

            if (updateUrl) updateHash(query, page);

            const t0 = performance.now();
            try {
                const r = await fetch('/api/search?q=' + encodeURIComponent(query) + '&page=' + page);
                if (!r.ok) throw new Error('Query failed: ' + r.status);
                const d = await r.json();
                renderResults(d, query, performance.now() - t0);
            } catch (e) {
                el.resultsList.innerHTML = '<div class="state-message"><div class="icon">!</div><h3>QUERY ERROR</h3><p>' + esc(e.message) + '</p></div>';
                el.resultsCount.textContent = '0';
                el.resultsTotalLabel.textContent = '';
                el.pagination.innerHTML = '';
            }
        }

        function renderResults(data, query, latency) {
            const { results: hits, total, page, per_page, total_pages } = data;
            el.resultsLatency.textContent = latency.toFixed(1) + 'ms';
            setResultsIntent(query);

            if (!hits || hits.length === 0) {
                el.resultsCount.textContent = '0';
                el.resultsTotalLabel.textContent = '';
                el.resultsList.innerHTML = '<div class="state-message"><div class="icon">[ ]</div><h3>NO MATCHES FOUND</h3><p>Query "' + esc(query) + '" returned no results.</p></div>';
                el.pagination.innerHTML = '';
                currentHits = [];
                currentTotalPages = 0;
                return;
            }

            currentHits = hits;
            currentTotal = total;
            currentTotalPages = total_pages;
            currentPerPage = per_page;
            selectedResultIndex = hits.length > 0 ? 0 : -1;
            el.resultsCount.textContent = hits.length;
            el.resultsTotalLabel.textContent = 'of ' + fmt(total) + ' total';

            renderResultsList();
            renderPagination(page, total_pages, total);
        }

        function renderResultsList() {
            const hits = sortHits(currentHits, currentSort);
            if (hits.length === 0) {
                el.resultsList.innerHTML = '';
                return;
            }
            const minScore = Math.min(...hits.map(h => Number(h.score || 0)));
            const maxScore = Math.max(...hits.map(h => Number(h.score || 0)));
            const startIdx = (currentPage - 1) * currentPerPage;

            el.resultsList.innerHTML = hits.map((h, i) => {
                const bins = (h.binary_names || []).map(b => '<span class="bin-tag">' + esc(b) + '</span>').join('');
                const displayName = h.func_name_demangled || h.func_name;
                const langBadge = h.lang ? '<span class="lang-badge">' + esc(h.lang.toUpperCase()) + '</span>' : '';
                const mangledHint = h.func_name_demangled ? '<div class="result-mangled" title="Mangled name">' + esc(h.func_name) + '</div>' : '';
                const scoreRatio = normalizeScore(Number(h.score || 0), minScore, maxScore);
                const isPinned = pinnedKeys.has(h.key_hex);
                const inCompare = compareKeys.includes(h.key_hex);
                const isPreviewOpen = openPreviewKey === h.key_hex;
                const isSelected = i === selectedResultIndex;
                const age = fmtRelativeTs(h.ts);
                const copied = copiedKeyHex === h.key_hex;

                return '<div class="result-item clickable' + (isSelected ? ' selected' : '') + '" data-result-index="' + i + '" onclick="showFunctionDetail(\'' + esc(h.key_hex) + '\')">'
                    + '<div class="result-index">' + String(startIdx + i + 1).padStart(2, '0') + '</div>'
                    + '<div class="result-main"><div class="result-func">' + esc(displayName) + '</div>' + mangledHint + '<div class="result-key"><span class="result-key-copy' + (copied ? ' copied' : '') + '" onclick="event.stopPropagation();copyResultKey(\'' + esc(h.key_hex) + '\')">KEY ' + esc(h.key_hex) + '</span><span class="result-age">' + esc(age) + '</span></div><div class="result-bins">' + bins + '</div></div>'
                    + '<div class="result-meta">' + langBadge + '<span class="version-badge age">' + esc(age) + '</span><span class="score-badge">SCORE ' + Number(h.score).toFixed(2) + '</span><div class="score-meter"><div class="score-meter-fill" style="width:' + (scoreRatio * 100).toFixed(1) + '%;"></div></div><div class="result-actions">'
                    + '<button class="result-action' + (isPinned ? ' active' : '') + '" onclick="event.stopPropagation();togglePin(\'' + esc(h.key_hex) + '\')">pin</button>'
                    + '<button class="result-action' + (inCompare ? ' active' : '') + '" onclick="event.stopPropagation();toggleCompareKey(\'' + esc(h.key_hex) + '\')">cmp</button>'
                    + '<button class="result-action' + (isPreviewOpen ? ' active' : '') + '" onclick="event.stopPropagation();togglePreview(\'' + esc(h.key_hex) + '\')">peek</button>'
                    + '</div></div>'
                    + '<div class="result-preview' + (isPreviewOpen ? ' active' : '') + '">' + (isPreviewOpen ? previewHtmlForKey(h.key_hex) : '') + '</div>'
                    + '</div>';
            }).join('');
        }

        function renderPagination(page, totalPages, total) {
            if (totalPages <= 1) {
                el.pagination.innerHTML = '';
                return;
            }

            let html = '<button class="pagination-btn" onclick="goToPage(' + (page - 1) + ')"' + (page <= 1 ? ' disabled' : '') + '>&lt;&lt; PREV</button>';
            html += '<span class="pagination-info">PAGE <span class="accent">' + page + '</span> OF <span class="accent">' + totalPages + '</span></span>';
            html += '<button class="pagination-btn" onclick="goToPage(' + (page + 1) + ')"' + (page >= totalPages ? ' disabled' : '') + '>NEXT &gt;&gt;</button>';

            el.pagination.innerHTML = html;
        }

        function goToPage(page) {
            if (page < 1 || !currentQuery) return;
            runSearch(currentQuery, page, true);
            window.scrollTo({ top: 0, behavior: 'smooth' });
        }

        function setSelectedResultIndex(idx) {
            const hits = sortHits(currentHits, currentSort);
            if (hits.length === 0) {
                selectedResultIndex = -1;
                return;
            }
            selectedResultIndex = Math.max(0, Math.min(hits.length - 1, idx));
            renderResultsList();
            const row = document.querySelector('[data-result-index="' + selectedResultIndex + '"]');
            if (row) row.scrollIntoView({ block: 'nearest' });
        }

        function handleResultsKeyNav(e) {
            if (!el.results.classList.contains('active') || el.detailModal.classList.contains('active')) return;
            if (document.activeElement === el.q || document.activeElement === el.resultsSort) return;
            const hits = sortHits(currentHits, currentSort);
            if (hits.length === 0) return;

            if (e.key === 'j') {
                e.preventDefault();
                setSelectedResultIndex(selectedResultIndex < 0 ? 0 : selectedResultIndex + 1);
            } else if (e.key === 'k') {
                e.preventDefault();
                setSelectedResultIndex(selectedResultIndex < 0 ? 0 : selectedResultIndex - 1);
            } else if (e.key === 'Enter' && selectedResultIndex >= 0) {
                e.preventDefault();
                showFunctionDetail(hits[selectedResultIndex].key_hex);
            } else if (e.key === ' ') {
                if (selectedResultIndex >= 0) {
                    e.preventDefault();
                    togglePreview(hits[selectedResultIndex].key_hex);
                }
            } else if (e.key === 'c' && selectedResultIndex >= 0) {
                e.preventDefault();
                toggleCompareKey(hits[selectedResultIndex].key_hex);
            } else if (e.key === 'p' && selectedResultIndex >= 0) {
                e.preventDefault();
                togglePin(hits[selectedResultIndex].key_hex);
            }
        }

        function handleSearchInput() {
            if (searchDebounceTimer) clearTimeout(searchDebounceTimer);
            searchDebounceTimer = setTimeout(() => runSearch(el.q.value, 1), DEBOUNCE_MS);
        }

        el.q.addEventListener('input', handleSearchInput);
        el.q.addEventListener('keydown', e => {
            if (e.key === 'Enter') {
                if (searchDebounceTimer) { clearTimeout(searchDebounceTimer); searchDebounceTimer = null; }
                runSearch(el.q.value, 1);
            }
        });
        document.addEventListener('keydown', e => {
            if (e.key === '/' && document.activeElement !== el.q) { e.preventDefault(); el.q.focus(); }
        });
        document.addEventListener('keydown', handleResultsKeyNav);

        el.resultsSort.addEventListener('change', e => {
            currentSort = e.target.value || 'score';
            renderResultsList();
        });
        el.compareClear.addEventListener('click', clearCompareKeys);
        el.compareOpen.addEventListener('click', openCompareModal);
        window.addEventListener('hashchange', () => {
            const { q, page } = parseHash();
            el.q.value = q;
            if (q) runSearch(q, page, false); else showDashboard();
        });

        updateTime();
        setInterval(updateTime, 1000);
        fetchMetrics();
        setInterval(fetchMetrics, 5000);
        updateCompareTray();
        el.resultsSort.value = currentSort;

        const init = parseHash();
        if (init.q) { el.q.value = init.q; runSearch(init.q, init.page, false); }

        // ═══════════════════════════════════════════════════════════════
        // FUNCTION DETAIL MODAL
        // ═══════════════════════════════════════════════════════════════

        function showFunctionDetail(keyHex) {
            currentDetailData = null;
            el.modalKey.textContent = keyHex;
            el.modalBody.innerHTML = '<div class="detail-loading">&gt;&gt;&gt; LOADING METADATA...</div>';
            el.detailModal.classList.add('active');
            document.body.style.overflow = 'hidden';

            fetch('/api/function/' + encodeURIComponent(keyHex))
                .then(r => {
                    if (!r.ok) throw new Error('Failed to fetch: ' + r.status);
                    return r.json();
                })
                .then(data => renderFunctionDetail(data))
                .catch(err => {
                    el.modalBody.innerHTML = '<div class="state-message"><div class="icon">!</div><h3>FETCH ERROR</h3><p>' + esc(err.message) + '</p></div>';
                });
        }

        function closeDetailModal() {
            el.detailModal.classList.remove('active');
            document.body.style.overflow = '';
            currentDetailData = null;
            if (activeCommentRow) {
                activeCommentRow.classList.remove('active');
                activeCommentRow = null;
            }
            if (activeCommentRowTimer) {
                clearTimeout(activeCommentRowTimer);
                activeCommentRowTimer = null;
            }
            if (activeCommentMarker) {
                activeCommentMarker.classList.remove('active');
                activeCommentMarker = null;
            }
            if (activeCommentMarkerTimer) {
                clearTimeout(activeCommentMarkerTimer);
                activeCommentMarkerTimer = null;
            }
        }

        el.detailModal.addEventListener('click', e => {
            if (e.target === el.detailModal) closeDetailModal();
        });

        document.addEventListener('keydown', e => {
            if (e.key === 'Escape' && el.detailModal.classList.contains('active')) {
                closeDetailModal();
            }
        });

        function renderFunctionDetail(data) {
            if (data.error) {
                el.modalBody.innerHTML = '<div class="state-message"><div class="icon">!</div><h3>ERROR</h3><p>' + esc(data.error) + '</p></div>';
                return;
            }

            currentDetailData = data;

            const m = data.metadata || {};
            const parseBadge = (m.errors && m.errors.length > 0) ? 'PARTIAL' : 'PARSED';

            const sections = [
                { id: 'section-overview', label: 'Overview' },
                { id: 'section-health', label: 'Health' },
            ];
            if (m.fcmt || m.frptcmt || m.vd_elapsed !== null) sections.push({ id: 'section-attrs', label: 'Attributes' });
            if (m.type_parts) sections.push({ id: 'section-type', label: 'Type' });
            if (m.frame_desc) sections.push({ id: 'section-frame', label: 'Frame' });
            if (((m.insn_cmts || []).length + (m.rpt_insn_cmts || []).length) > 0) sections.push({ id: 'section-comments', label: 'Comments' });
            if ((m.errors || []).length > 0) sections.push({ id: 'section-errors', label: 'Errors' });

            let html = '<div class="detail-layout">';
            html += '<div class="detail-nav">';
            sections.forEach((s, i) => {
                html += '<button data-target="' + s.id + '" class="' + (i === 0 ? 'active' : '') + '" onclick="jumpToDetailSection(\'' + s.id + '\');setActiveDetailNav(\'' + s.id + '\');">' + esc(s.label) + '</button>';
            });
            html += '</div><div class="detail-main">';

            // Function name
            html += '<div class="detail-section detail-anchor" id="section-overview"><div class="detail-label">Function Name</div><div class="detail-value accent">' + esc(data.name) + '</div></div>';

            // Key
            html += '<div class="detail-section"><div class="detail-label">Function Key</div><div class="detail-value mono">' + esc(data.key_hex) + '</div></div>';

            // Stats grid
            html += '<div class="detail-grid">';
            html += '<div class="detail-stat"><div class="label">Data Size</div><div class="value">' + fmtBytes(data.data_size || 0) + '</div></div>';
            html += '<div class="detail-stat"><div class="label">Metadata State</div><div class="value">' + esc(parseBadge) + '</div></div>';
            html += '<div class="detail-stat"><div class="label">Age</div><div class="value">' + esc(fmtRelativeTs(data.ts)) + '</div></div>';
            html += '</div>';

            html += renderParseHealth(m);

            // Binary names
            if (data.binary_names && data.binary_names.length > 0) {
                html += '<div class="detail-section"><div class="detail-label">Associated Binaries</div><div class="result-bins">';
                data.binary_names.forEach(b => { html += '<span class="bin-tag">' + esc(b) + '</span>'; });
                html += '</div></div>';
            }

            // Metadata sections
            if (m) {
                // Function Comments (MDK_FCMT / MDK_FRPTCMT)
                if (m.fcmt || m.frptcmt || m.vd_elapsed !== null) {
                    html += '<div class="metadata-section detail-anchor" id="section-attrs"><div class="metadata-header"><span>Function Attributes</span></div><div class="metadata-content" style="display: flex; flex-direction: column; gap: var(--space-md);">';
                    
                    if (m.vd_elapsed !== null && m.vd_elapsed !== undefined) {
                        html += '<div class="detail-stat" style="width: max-content;"><div class="label">Decompilation Time</div><div class="value">' + m.vd_elapsed + ' seconds</div></div>';
                    }

                    if (m.fcmt) {
                        html += '<div class="detail-section"><div class="detail-label">Regular Comment</div><div class="detail-value mono" style="white-space: pre-wrap;">' + esc(m.fcmt) + '</div></div>';
                    }

                    if (m.frptcmt) {
                        html += '<div class="detail-section"><div class="detail-label">Repeatable Comment</div><div class="detail-value mono" style="white-space: pre-wrap;">' + esc(m.frptcmt) + '</div></div>';
                    }
                    
                    html += '</div></div>';
                }

                // Type Parts (MDK_TYPE)
                if (m.type_parts) {
                    html += '<div class="metadata-section detail-anchor" id="section-type"><div class="metadata-header"><span>MDK_TYPE Data</span><span class="badge nominal">PRESENT</span></div><div class="metadata-content">';
                    html += renderTypeSignature(m.type_parts);
                    html += '</div></div>';
                }

                // Frame Desc (MDK_FRAME_DESC)
                if (m.frame_desc) {
                    const fd = m.frame_desc;
                    html += '<div class="metadata-section detail-anchor" id="section-frame"><div class="metadata-header"><span>Frame Descriptor</span><span class="badge">' + (fd.members ? fd.members.length : 0) + ' MEMBERS</span></div><div class="metadata-content">';
                    
                    html += '<div class="detail-grid" style="margin-bottom: var(--space-md);">';
                    html += '<div class="detail-stat"><div class="label">Frame Size</div><div class="value">0x' + (fd.frsize || 0).toString(16) + '</div></div>';
                    html += '<div class="detail-stat"><div class="label">Arg Size</div><div class="value">0x' + (fd.argsize || 0).toString(16) + '</div></div>';
                    html += '<div class="detail-stat"><div class="label">Saved Regs</div><div class="value">0x' + (fd.frregs || 0).toString(16) + '</div></div>';
                    html += '</div>';

                    html += renderFrameDiagnostics(fd);
                    html += renderFrameDescriptor(fd);
                    html += '</div></div>';
                }

                // Instruction Comments Timeline
                const regCount = Array.isArray(m.insn_cmts) ? m.insn_cmts.length : 0;
                const rptCount = Array.isArray(m.rpt_insn_cmts) ? m.rpt_insn_cmts.length : 0;
                const totalCommentCount = regCount + rptCount;
                if (totalCommentCount > 0) {
                    html += '<div class="metadata-section detail-anchor" id="section-comments"><div class="metadata-header"><span>Instruction Comment Timeline</span><span class="badge">' + totalCommentCount + '</span></div><div class="metadata-content">';
                    html += renderInstructionCommentTimeline(m.insn_cmts, m.rpt_insn_cmts);
                    html += '</div></div>';
                }

                // Raw stats
                if (m.errors && m.errors.length > 0) {
                    html += '<div class="state-message detail-anchor" id="section-errors" style="margin-top: var(--space-md); border-color: var(--state-warning); background: rgba(255, 102, 0, 0.1);"><div class="icon" style="color: var(--state-warning);">!</div><h3 style="color: var(--state-warning);">PARSE ERRORS</h3><ul style="text-align: left; margin-top: var(--space-sm);">';
                    m.errors.forEach(err => {
                        html += '<li>' + esc(err) + '</li>';
                    });
                    html += '</ul></div>';
                }
            }

            html += '</div></div>';
            el.modalBody.innerHTML = html;
        }
    </script>
</body>
</html>
"#;
