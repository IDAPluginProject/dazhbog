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

        .compare-panel {
            display: flex;
            flex-wrap: wrap;
            justify-content: space-between;
            align-items: center;
            gap: var(--space-md);
            margin: var(--space-lg) 0 var(--space-xl);
            border: 1px solid var(--border-subtle);
            background: linear-gradient(180deg, rgba(255,255,255,0.01), rgba(255,255,255,0.02));
            padding: var(--space-md);
        }

        .compare-panel.hidden {
            display: none;
        }

        .compare-panel.compact {
            padding: 10px 12px;
        }

        .compare-panel-head {
            display: flex;
            align-items: center;
            gap: var(--space-md);
            flex-wrap: wrap;
            min-width: 0;
        }

        .compare-panel .compare-title {
            color: var(--accent);
            letter-spacing: 0.1em;
            text-transform: uppercase;
        }

        .compare-panel-summary {
            font-size: 10px;
            color: var(--text-dim);
            letter-spacing: 0.08em;
        }

        .compare-panel-actions {
            display: flex;
            align-items: center;
            gap: 8px;
            flex-wrap: wrap;
        }

        .compare-panel-actions select {
            background: var(--bg-base);
            border: 1px solid var(--border-dim);
            color: var(--text-secondary);
            font-family: var(--font-mono);
            font-size: 10px;
            padding: 5px 8px;
        }

        .compare-panel-list {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            width: 100%;
        }

        .compare-pill {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            border: 1px solid rgba(0, 255, 136, 0.25);
            background: rgba(0, 255, 136, 0.08);
            padding: 6px 8px;
            min-width: 0;
            max-width: 100%;
        }

        .compare-pill.loading {
            border-style: dashed;
            opacity: 0.78;
        }

        .compare-pill.baseline {
            border-color: rgba(255, 170, 0, 0.45);
            background: rgba(255, 170, 0, 0.08);
        }

        .compare-pill.dragging {
            opacity: 0.5;
        }

        .compare-pill-handle,
        .compare-pill-pin {
            background: var(--bg-base);
            border: 1px solid var(--border-dim);
            color: var(--text-secondary);
            font-family: var(--font-mono);
            font-size: 10px;
            padding: 3px 6px;
            cursor: grab;
        }

        .compare-pill-pin {
            cursor: pointer;
        }

        .compare-pill-pin.active {
            color: var(--state-warning);
            border-color: rgba(255, 170, 0, 0.45);
        }

        .compare-pill-main {
            display: flex;
            flex-direction: column;
            gap: 2px;
            min-width: 0;
        }

        .compare-pill-name {
            color: var(--accent);
            font-size: 11px;
            font-weight: 600;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            max-width: 320px;
        }

        .compare-pill-key {
            color: var(--text-tertiary);
            font-size: 9px;
            font-family: var(--font-mono);
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            max-width: 320px;
        }

        .compare-pill-status {
            color: var(--text-dim);
            font-size: 9px;
            letter-spacing: 0.08em;
            text-transform: uppercase;
        }

        .compare-pill-remove {
            background: var(--bg-base);
            border: 1px solid var(--border-dim);
            color: var(--text-secondary);
            font-family: var(--font-mono);
            font-size: 10px;
            padding: 3px 7px;
            cursor: pointer;
        }

        .compare-pill-remove:hover {
            color: var(--state-warning);
            border-color: rgba(255, 102, 0, 0.4);
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

        .compare-toolbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: var(--space-md);
            flex-wrap: wrap;
        }

        .compare-toolbar-group {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            align-items: center;
        }

        .compare-toggle {
            background: var(--bg-base);
            border: 1px solid var(--border-dim);
            color: var(--text-secondary);
            font-family: var(--font-mono);
            font-size: 10px;
            padding: 5px 9px;
            cursor: pointer;
            text-transform: uppercase;
            letter-spacing: 0.08em;
        }

        .compare-toggle.active {
            color: var(--accent);
            border-color: rgba(0, 255, 136, 0.35);
            background: rgba(0, 255, 136, 0.08);
        }

        .compare-status {
            color: var(--text-dim);
            font-size: 10px;
            letter-spacing: 0.08em;
            text-transform: uppercase;
        }

        .compare-head {
            display: grid;
            grid-template-columns: 180px repeat(var(--compare-cols, 2), minmax(0, 1fr));
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
            grid-template-columns: 180px repeat(var(--compare-cols, 2), minmax(0, 1fr));
            gap: 1px;
            background: var(--border-dim);
        }

        .compare-row.jumpable {
            cursor: pointer;
        }

        .compare-row.jumpable:hover .compare-cell,
        .compare-row.jumpable:hover .compare-label {
            background: rgba(0, 255, 136, 0.05);
        }

        .compare-row.unchanged {
            display: none;
        }

        .compare-diff.show-all .compare-row.unchanged {
            display: grid;
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

        .compare-cell .diff-add {
            background: rgba(0, 255, 136, 0.16);
            color: var(--accent);
            padding: 0 1px;
        }

        .compare-cell .diff-del {
            background: rgba(255, 102, 0, 0.16);
            color: var(--state-warning);
            padding: 0 1px;
        }

        .compare-subsection {
            border-top: 1px solid var(--border-subtle);
            padding: 10px;
            background: var(--bg-panel);
        }

        .compare-subtitle {
            color: var(--text-dim);
            font-size: 10px;
            letter-spacing: 0.1em;
            text-transform: uppercase;
            margin-bottom: 8px;
        }

        .detail-anchor {
            scroll-margin-top: 14px;
        }

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

        .comment-item.active-controlflow .comment-item-head,
        .comment-item.active-controlflow .comment-item-text {
            background: rgba(255, 170, 0, 0.08);
            box-shadow: inset 2px 0 0 rgba(255, 170, 0, 0.9);
        }

        .comment-item.dimmed {
            opacity: 0.42;
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

        .controlflow-grid {
            display: grid;
            grid-template-columns: minmax(240px, 0.9fr) minmax(0, 1.6fr);
            gap: var(--space-md);
        }

        .controlflow-panel {
            border: 1px solid var(--border-subtle);
            background: var(--bg-panel);
            padding: var(--space-md);
            transition: opacity 140ms ease, transform 140ms ease, border-color 140ms ease;
        }

        .controlflow-panel.dimmed,
        .switch-group.dimmed,
        .jumptable-card.dimmed {
            opacity: 0.42;
        }

        .controlflow-toolbar {
            display: flex;
            justify-content: space-between;
            gap: var(--space-md);
            flex-wrap: wrap;
            align-items: center;
            border: 1px solid var(--border-subtle);
            background: var(--bg-panel);
            padding: 10px 12px;
            margin-bottom: var(--space-md);
        }

        .controlflow-toolbar-summary,
        .controlflow-toolbar-actions {
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
            align-items: center;
        }

        .controlflow-active-filter {
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }

        .controlflow-focus-note {
            color: var(--text-dim);
            font-size: 11px;
            letter-spacing: 0.04em;
            text-transform: uppercase;
        }

        .controlflow-matrix {
            border: 1px solid var(--border-subtle);
            background: var(--border-dim);
            margin-bottom: var(--space-md);
        }

        .controlflow-matrix-row {
            display: grid;
            grid-template-columns: 150px minmax(0, 1fr);
            gap: 1px;
            background: var(--border-dim);
            cursor: pointer;
            transition: background 120ms ease;
        }

        .controlflow-matrix-row:hover .controlflow-matrix-cell,
        .controlflow-matrix-row.active .controlflow-matrix-cell {
            background: rgba(0, 255, 136, 0.05);
        }

        .controlflow-matrix-row + .controlflow-matrix-row {
            border-top: 1px solid var(--border-subtle);
        }

        .controlflow-matrix-cell {
            background: var(--bg-panel);
            padding: 8px 10px;
            min-width: 0;
        }

        .controlflow-matrix-label {
            color: var(--text-dim);
            font-size: 10px;
            letter-spacing: 0.08em;
            text-transform: uppercase;
        }

        .controlflow-matrix-value {
            color: var(--text-secondary);
            font-family: var(--font-mono);
            font-size: 11px;
            overflow-wrap: anywhere;
        }

        .controlflow-hero {
            border: 1px solid var(--border-subtle);
            background: var(--bg-panel);
            padding: var(--space-md);
            margin-bottom: var(--space-md);
        }

        .controlflow-hero-title {
            color: var(--state-warning);
            font-size: 10px;
            letter-spacing: 0.12em;
            text-transform: uppercase;
            margin-bottom: 6px;
        }

        .controlflow-hero-main {
            display: flex;
            justify-content: space-between;
            gap: var(--space-md);
            flex-wrap: wrap;
            align-items: center;
        }

        .controlflow-hero-addr {
            color: var(--text-primary);
            font-family: var(--font-mono);
            font-size: 14px;
            overflow-wrap: anywhere;
        }

        .controlflow-hero-stats {
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
        }

        .controlflow-stack {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }

        .switch-card {
            border: 1px solid var(--border-subtle);
            background: var(--bg-base);
            padding: 10px;
        }

        .switch-group {
            border: 1px solid var(--border-subtle);
            background: var(--bg-base);
        }

        .switch-group.collapsed .switch-group-body {
            display: none;
        }

        .switch-group-head {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 8px;
            padding: 10px;
            cursor: pointer;
            background: rgba(255,255,255,0.01);
            border-bottom: 1px solid var(--border-subtle);
        }

        .switch-group-body {
            padding: 8px;
            display: flex;
            flex-direction: column;
            gap: 8px;
        }

        .switch-group-title {
            color: var(--accent);
            font-size: 11px;
            letter-spacing: 0.08em;
            text-transform: uppercase;
        }

        .switch-card:hover,
        .switch-card.active,
        .switch-card.linked {
            border-color: rgba(0, 255, 136, 0.28);
            background: rgba(0, 255, 136, 0.04);
        }

        .switch-card.active {
            border-color: rgba(255, 170, 0, 0.46);
            background: rgba(255, 170, 0, 0.06);
        }

        .switch-card-head {
            display: flex;
            justify-content: space-between;
            gap: 8px;
            align-items: center;
            margin-bottom: 6px;
        }

        .switch-title {
            color: var(--accent);
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.08em;
            text-transform: uppercase;
        }

        .switch-meta {
            color: var(--text-dim);
            font-family: var(--font-mono);
            font-size: 10px;
        }

        .switch-desc {
            color: var(--text-primary);
            font-family: var(--font-mono);
            font-size: 12px;
            overflow-wrap: anywhere;
        }

        .switch-summary {
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
            margin-top: 8px;
        }

        .controlflow-group-strip {
            display: flex;
            flex-direction: column;
            gap: 6px;
            padding: 8px 10px;
            border-top: 1px solid var(--border-subtle);
            background: rgba(255, 255, 255, 0.015);
        }

        .controlflow-group-strip-head {
            display: flex;
            justify-content: space-between;
            gap: 8px;
            flex-wrap: wrap;
            align-items: center;
        }

        .controlflow-group-strip-label {
            color: var(--text-dim);
            font-size: 10px;
            letter-spacing: 0.08em;
            text-transform: uppercase;
        }

        .controlflow-density-strip {
            display: grid;
            grid-template-columns: repeat(18, minmax(0, 1fr));
            gap: 3px;
        }

        .controlflow-density-bin {
            height: 10px;
            border: 1px solid var(--border-dim);
            background: var(--bg-base);
        }

        button.controlflow-density-bin {
            padding: 0;
            cursor: pointer;
        }

        .controlflow-density-bin.fill {
            background: rgba(0, 255, 136, 0.32);
            border-color: rgba(0, 255, 136, 0.18);
        }

        .controlflow-density-bin.default {
            background: rgba(255, 170, 0, 0.42);
            border-color: rgba(255, 170, 0, 0.24);
        }

        .controlflow-density-bin.active {
            box-shadow: inset 0 0 0 1px rgba(255, 255, 255, 0.35), 0 0 0 1px rgba(255, 170, 0, 0.35);
        }

        .controlflow-density-bin:hover {
            transform: translateY(-1px);
        }

        .controlflow-legend {
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
            margin-bottom: var(--space-md);
        }

        .jumptable-card {
            border: 1px solid var(--border-subtle);
            background: var(--bg-panel);
            overflow: hidden;
        }

        .jumptable-head {
            display: flex;
            justify-content: space-between;
            gap: var(--space-md);
            flex-wrap: wrap;
            padding: 10px 12px;
            background: var(--bg-element);
            border-bottom: 1px solid var(--border-subtle);
        }

        .jumptable-title {
            color: var(--accent);
            font-family: var(--font-mono);
            font-size: 12px;
            overflow-wrap: anywhere;
        }

        .jumptable-badges {
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
        }

        .jumptable-cluster-note {
            margin-top: 6px;
            color: var(--text-dim);
            font-size: 10px;
            letter-spacing: 0.06em;
            text-transform: uppercase;
        }

        .jumptable-coverage {
            border-top: 1px solid var(--border-subtle);
            padding: 10px 12px 8px;
            background: rgba(255,255,255,0.01);
        }

        .jumptable-coverage-strip {
            display: grid;
            grid-template-columns: repeat(24, minmax(0, 1fr));
            gap: 3px;
            margin-top: 8px;
        }

        .coverage-bin {
            height: 14px;
            border: 1px solid var(--border-dim);
            background: var(--bg-base);
            position: relative;
            overflow: hidden;
        }

        .coverage-bin.fill::before {
            content: "";
            position: absolute;
            inset: 0;
            background: rgba(0,255,136,0.45);
        }

        .coverage-bin.default::before {
            background: rgba(255,170,0,0.55);
        }

        .coverage-bin.active {
            box-shadow: 0 0 0 1px rgba(255, 170, 0, 0.4);
        }

        .coverage-meta {
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
            margin-top: 8px;
        }

        .jumptable-more {
            margin-top: 8px;
        }

        .controlflow-toggle {
            background: var(--bg-base);
            border: 1px solid var(--border-dim);
            color: var(--text-secondary);
            font-family: var(--font-mono);
            font-size: 10px;
            padding: 4px 8px;
            cursor: pointer;
        }

        .controlflow-toggle:hover {
            border-color: rgba(0, 255, 136, 0.28);
            color: var(--text-primary);
        }

        .jumptable-ref-list {
            display: flex;
            flex-direction: column;
        }

        .jumptable-ref {
            display: grid;
            grid-template-columns: 96px minmax(0, 1fr);
            gap: 1px;
            background: var(--border-dim);
        }

        .jumptable-ref + .jumptable-ref {
            border-top: 1px solid var(--border-subtle);
        }

        .jumptable-ref.active .jumptable-ref-meta,
        .jumptable-ref.active .jumptable-ref-body {
            background: rgba(255, 170, 0, 0.06);
            box-shadow: inset 2px 0 0 rgba(255, 170, 0, 0.92);
        }

        .jumptable-ref-meta,
        .jumptable-ref-body {
            background: var(--bg-panel);
            padding: 6px 8px;
            min-width: 0;
        }

        .jumptable-ref-meta {
            color: var(--text-dim);
            font-family: var(--font-mono);
            font-size: 9px;
            line-height: 1.35;
        }

        .jumptable-ref-body {
            color: var(--text-secondary);
            font-family: var(--font-mono);
            font-size: 11px;
            overflow-wrap: anywhere;
        }

        .jumptable-case-strip {
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
            margin-top: 8px;
        }

        .case-chip {
            border: 1px solid rgba(0, 255, 136, 0.28);
            background: rgba(0, 255, 136, 0.08);
            color: var(--accent);
            padding: 2px 6px;
            font-size: 10px;
            font-family: var(--font-mono);
        }

        button.case-chip {
            cursor: pointer;
        }

        .case-chip.default {
            border-color: rgba(255, 170, 0, 0.4);
            background: rgba(255, 170, 0, 0.1);
            color: var(--state-warning);
        }

        .case-chip.active {
            border-color: rgba(255, 170, 0, 0.55);
            background: rgba(255, 170, 0, 0.16);
            color: var(--text-primary);
        }

        .jumptable-graph {
            border: 1px solid var(--border-subtle);
            background: var(--bg-base);
            padding: 10px;
            display: flex;
            flex-direction: column;
            gap: 8px;
        }

        .jumptable-ref.linked,
        .comment-item.linked {
            box-shadow: inset 2px 0 0 rgba(0, 255, 136, 0.7);
            background: rgba(0, 255, 136, 0.04);
        }

        .controlflow-actions {
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
            margin-top: 8px;
        }

        .switch-links {
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
            margin-top: 8px;
        }

        .relation-summary {
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
            align-items: center;
            margin-bottom: 4px;
        }

        .relation-detail {
            color: var(--text-dim);
            font-size: 10px;
            line-height: 1.3;
        }

        .comment-item-text.controlflow {
            display: flex;
            flex-direction: column;
            gap: 6px;
        }

        .comment-flow-main {
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
            align-items: center;
        }

        .comment-flow-detail {
            color: var(--text-dim);
            font-size: 11px;
            line-height: 1.35;
        }

        .jumptable-graph-node {
            border: 1px solid var(--border-dim);
            background: var(--bg-base);
            padding: 8px 10px;
        }

        .jumptable-graph-node.active {
            border-color: rgba(255, 170, 0, 0.4);
            background: rgba(255, 170, 0, 0.05);
        }

        .jumptable-graph-node.root {
            border-color: rgba(0, 255, 136, 0.35);
        }

        .jumptable-graph-label {
            color: var(--text-dim);
            font-size: 9px;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            margin-bottom: 4px;
        }

        .jumptable-graph-value {
            color: var(--text-secondary);
            font-family: var(--font-mono);
            font-size: 12px;
            overflow-wrap: anywhere;
        }

        .jumptable-graph-badges {
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
            margin-top: 6px;
        }

        .jumptable-graph-edge {
            border-left: 1px solid rgba(0, 255, 136, 0.3);
            margin-left: 12px;
            padding-left: 14px;
            display: flex;
            flex-direction: column;
            gap: 8px;
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

            .compare-panel {
                align-items: flex-start;
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

            .controlflow-grid,
            .jumptable-ref {
                grid-template-columns: 1fr;
            }

            .controlflow-matrix-row {
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

        <section class="compare-panel compact hidden" id="compare-panel">
            <div class="compare-panel-head">
                <span class="compare-title">Compare Panel</span>
                <span class="compare-panel-summary" id="compare-summary">No functions queued</span>
            </div>
            <div class="compare-panel-actions">
                <button class="pagination-btn" id="compare-open" disabled>Open Compare</button>
                <button class="pagination-btn" id="compare-clear">Clear</button>
                <button class="pagination-btn" id="compare-save">Save Set</button>
                <button class="pagination-btn" id="compare-export">Export JSON</button>
                <button class="pagination-btn" id="compare-import">Import JSON</button>
                <select id="compare-load"><option value="">Load Set</option></select>
            </div>
            <div class="compare-panel-list" id="compare-list"></div>
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

        <input type="file" id="compare-import-file" accept="application/json,.json" style="display:none;">

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
            comparePanel: document.getElementById('compare-panel'),
            compareSummary: document.getElementById('compare-summary'),
            compareList: document.getElementById('compare-list'),
            compareOpen: document.getElementById('compare-open'),
            compareClear: document.getElementById('compare-clear'),
            compareSave: document.getElementById('compare-save'),
            compareExport: document.getElementById('compare-export'),
            compareImport: document.getElementById('compare-import'),
            compareLoad: document.getElementById('compare-load'),
            compareImportFile: document.getElementById('compare-import-file'),
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
            mVconsidered: document.getElementById('m-vconsidered'),
            mFallback: document.getElementById('m-fallback'),
            rateTotalRec: document.getElementById('rate-totalrec'),
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
        const compareItems = new Map();
        const resultPreviewCache = new Map();
        let compareBaselineKey = null;
        let draggingCompareKey = null;
        const compareHydrating = new Set();
        const expandedJumpTables = new Set();
        const collapsedSwitchGroups = new Set();
        let selectedControlFlowGroup = null;
        let selectedControlFlowRow = null;
        let selectedControlFlowCase = null;
        let controlFlowFocusMode = false;
        let compareShowAll = false;
        let compareMode = 'summary';

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

        function easeOutExpo(t) {
            return t >= 1 ? 1 : 1 - Math.pow(2, -10 * t);
        }

        function counterDuration(from, to, baseDuration) {
            const delta = Math.abs(to - from);
            const magnitude = Math.max(Math.abs(from), Math.abs(to), 1);
            const scaleBoost = Math.min(1.45, 1 + (Math.log10(magnitude + 1) * 0.08));
            const deltaBoost = Math.min(1.35, 1 + (Math.log10(delta + 1) * 0.06));
            return Math.max(420, Math.min(1650, baseDuration * scaleBoost * deltaBoost));
        }

        function snapAnimatedValue(value, delta) {
            if (delta < 25) return Math.round(value);
            if (delta < 1000) return Math.round(value / 5) * 5;
            if (delta < 100000) return Math.round(value / 25) * 25;
            if (delta < 10000000) return Math.round(value / 250) * 250;
            return Math.round(value / 1000) * 1000;
        }

        function animateMetricValue(node, nextValue, formatter = fmt, duration = 900) {
            if (!node) return;
            const id = node.id || String(Math.random());
            const prev = metricAnimationState.get(id);
            const to = Number(nextValue || 0);
            const from = prev && Number.isFinite(prev.current) ? prev.current : to;
            const tunedDuration = counterDuration(from, to, duration);
            const delta = Math.abs(to - from);
            if (!Number.isFinite(to)) {
                node.textContent = formatter(nextValue);
                return;
            }
            if (Math.abs(to - from) < 0.000001) {
                node.textContent = formatter(to);
                metricAnimationState.set(id, { current: to, raf: null });
                return;
            }
            if (prev && prev.raf) cancelAnimationFrame(prev.raf);
            const start = performance.now();
            const state = { current: from, raf: null };
            const tick = now => {
                const p = Math.min(1, (now - start) / tunedDuration);
                const eased = easeOutExpo(p);
                const value = from + ((to - from) * eased);
                const snapped = snapAnimatedValue(value, delta);
                state.current = value;
                node.textContent = formatter(snapped);
                if (p < 1) state.raf = requestAnimationFrame(tick);
                else {
                    state.current = to;
                    state.raf = null;
                    node.textContent = formatter(to);
                }
            };
            metricAnimationState.set(id, state);
            state.raf = requestAnimationFrame(tick);
        }

        function fmtWholeAnimated(n) {
            return fmt(Math.round(Number(n || 0)));
        }

        function fmtBytesAnimated(n) {
            return fmtBytes(Math.max(0, Math.round(Number(n || 0))));
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

        function buildControlFlowContext(cf) {
            const switches = Array.isArray(cf && cf.switches) ? cf.switches : [];
            const tables = Array.isArray(cf && cf.jumptables) ? cf.jumptables : [];

            function controlFlowId(kind, chunk, off) {
                return 'cf-' + String(kind || '').toLowerCase() + '-' + chunk + '-' + off;
            }

            const switchLinks = switches.map(sw => {
                let best = null;
                tables.forEach(jt => {
                    jt.refs.forEach(ref => {
                        if (ref.fchunk_nr !== sw.fchunk_nr) return;
                        const dist = Math.abs(Number(ref.fchunk_off) - Number(sw.fchunk_off));
                        if (!best || dist < best.dist) {
                            best = { addr: jt.addr, dist };
                        }
                    });
                });
                return best && best.dist <= 0x80 ? best.addr : null;
            });

            const tableSwitchCounts = new Map();
            switchLinks.forEach(addr => {
                if (!addr) return;
                tableSwitchCounts.set(addr, (tableSwitchCounts.get(addr) || 0) + 1);
            });

            const groupedSwitches = new Map();
            const rowToGroup = new Map();
            switches.forEach((sw, idx) => {
                const addr = switchLinks[idx] || '__unlinked__';
                if (!groupedSwitches.has(addr)) groupedSwitches.set(addr, []);
                groupedSwitches.get(addr).push(sw);
                rowToGroup.set(controlFlowId(sw.kind, sw.fchunk_nr, sw.fchunk_off), 'grp:' + addr);
            });

            tables.forEach(jt => {
                jt.refs.forEach(ref => {
                    rowToGroup.set(controlFlowId(ref.kind, ref.fchunk_nr, ref.fchunk_off), 'grp:' + jt.addr);
                });
            });

            return { switches, tables, switchLinks, tableSwitchCounts, groupedSwitches, rowToGroup, controlFlowId };
        }

        function renderCompactControlFlowStrip(labels, stats, groupId = null) {
            const bins = Array.isArray(labels) ? labels.slice(0, 18) : [];
            let html = '<div class="controlflow-group-strip">';
            html += '<div class="controlflow-group-strip-head">';
            html += '<div class="controlflow-group-strip-label">Case Density</div>';
            html += '<div class="controlflow-toolbar-summary">';
            stats.forEach(stat => {
                html += '<span class="frame-chip' + (stat.warn ? ' warn' : '') + '">' + esc(stat.label) + '</span>';
            });
            html += '</div></div>';
            html += '<div class="controlflow-density-strip">';
            bins.forEach(label => {
                const active = selectedControlFlowGroup === groupId && selectedControlFlowCase === label;
                html += '<button class="controlflow-density-bin fill' + (label === 'default' ? ' default' : '') + (active ? ' active' : '') + '" title="' + esc(label) + '" onclick="event.stopPropagation();setControlFlowCase(\'' + esc(groupId || '') + '\', \'' + esc(label) + '\')"></button>';
            });
            for (let i = bins.length; i < 18; i++) {
                html += '<div class="controlflow-density-bin"></div>';
            }
            html += '</div></div>';
            return html;
        }

        function controlFlowCaseMatches(ref, label) {
            if (!label) return true;
            if (!ref) return false;
            if (label === 'default') return !!ref.is_default || ref.source_role === 'default';
            return Array.isArray(ref.case_labels) && ref.case_labels.includes(label);
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
            if (compareKeys.length === 0) return 'No functions queued';
            if (compareKeys.length === 1) return '1 function queued';
            const baseline = compareBaselineKey ? (' // baseline ' + compareBaselineKey.slice(0, 8)) : '';
            return compareKeys.length + ' functions queued' + baseline;
        }

        function compareStorageKey() {
            return 'dazhbog.compareSets.v1';
        }

        function compareStateStorageKey() {
            return 'dazhbog.compareState.v1';
        }

        function loadCompareSets() {
            try {
                return JSON.parse(localStorage.getItem(compareStorageKey()) || '{}') || {};
            } catch (_) {
                return {};
            }
        }

        function storeCompareSets(sets) {
            localStorage.setItem(compareStorageKey(), JSON.stringify(sets));
        }

        function persistCompareState() {
            try {
                localStorage.setItem(compareStateStorageKey(), JSON.stringify({
                    keys: [...compareKeys],
                    baseline: compareBaselineKey,
                }));
            } catch (_) {}
        }

        function restoreCompareState() {
            try {
                const raw = localStorage.getItem(compareStateStorageKey());
                if (!raw) return;
                const state = JSON.parse(raw);
                if (!state || !Array.isArray(state.keys)) return;
                compareKeys.length = 0;
                state.keys.forEach(k => {
                    if (typeof k === 'string' && k) compareKeys.push(k);
                });
                compareBaselineKey = typeof state.baseline === 'string' ? state.baseline : (compareKeys[0] || null);
            } catch (_) {}
        }

        function refreshCompareLoadOptions() {
            const sets = loadCompareSets();
            const names = Object.keys(sets).sort();
            el.compareLoad.innerHTML = '<option value="">Load Set</option>' + names.map(name => '<option value="' + esc(name) + '">' + esc(name) + '</option>').join('');
        }

        function exportCompareSet() {
            if (compareKeys.length === 0) return;
            const payload = {
                name: 'compare-set',
                exported_at: new Date().toISOString(),
                keys: [...compareKeys],
                baseline: compareBaselineKey,
            };
            const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'dazhbog-compare-set.json';
            document.body.appendChild(a);
            a.click();
            a.remove();
            URL.revokeObjectURL(url);
        }

        function importCompareSetFromText(text) {
            const parsed = JSON.parse(text);
            if (!parsed || !Array.isArray(parsed.keys)) {
                throw new Error('invalid compare set file');
            }
            compareKeys.length = 0;
            parsed.keys.forEach(k => {
                if (typeof k === 'string' && k) compareKeys.push(k);
            });
            compareBaselineKey = typeof parsed.baseline === 'string' ? parsed.baseline : (compareKeys[0] || null);
            persistCompareState();
            updateCompareTray();
            renderResultsList();
            hydrateCompareItems(compareKeys);
        }

        function rememberCompareItem(hit) {
            if (!hit || !hit.key_hex) return;
            const prev = compareItems.get(hit.key_hex) || {};
            compareItems.set(hit.key_hex, {
                key_hex: hit.key_hex,
                name: hit.func_name_demangled || hit.func_name || hit.key_hex,
                ts: hit.ts || 0,
                loading: false,
                hydrated: true,
                detail: prev.detail || null,
            });
        }

        async function hydrateCompareItems(keys = compareKeys) {
            const missing = keys.filter(keyHex => {
                const item = compareItems.get(keyHex);
                return (!item || item.name === keyHex || !item.ts) && !compareHydrating.has(keyHex);
            });
            if (missing.length === 0) return;

            missing.forEach(keyHex => {
                compareHydrating.add(keyHex);
                const prev = compareItems.get(keyHex) || { key_hex: keyHex, name: keyHex, ts: 0 };
                compareItems.set(keyHex, { ...prev, loading: true });
            });
            updateCompareTray();

            await Promise.all(missing.map(async keyHex => {
                try {
                    const resp = await fetch('/api/function/' + encodeURIComponent(keyHex));
                    if (!resp.ok) return;
                    const data = await resp.json();
                    if (data && !data.error) {
                        compareItems.set(keyHex, {
                            key_hex: keyHex,
                            name: data.name || keyHex,
                            ts: data.ts || 0,
                            loading: false,
                            hydrated: true,
                            detail: data,
                        });
                    }
                } catch (_) {}
                finally {
                    compareHydrating.delete(keyHex);
                    const prev = compareItems.get(keyHex);
                    if (prev && prev.loading) {
                        compareItems.set(keyHex, { ...prev, loading: false });
                    }
                }
            }));

            updateCompareTray();
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
            if (compareBaselineKey && !compareKeys.includes(compareBaselineKey)) {
                compareBaselineKey = compareKeys[0] || null;
            }
            el.compareSummary.textContent = compareTextForKeys();
            el.compareOpen.disabled = compareKeys.length < 2;
            el.comparePanel.classList.toggle('compact', compareKeys.length === 0);
            el.compareList.innerHTML = compareKeys.map(keyHex => {
                const item = compareItems.get(keyHex) || { key_hex: keyHex, name: keyHex, ts: 0, loading: false };
                const baseline = compareBaselineKey === keyHex;
                return '<div class="compare-pill' + (baseline ? ' baseline' : '') + (item.loading ? ' loading' : '') + '" draggable="true" ondragstart="startCompareDrag(\'' + esc(keyHex) + '\')" ondragover="allowCompareDrop(event)" ondrop="dropCompareKey(\'' + esc(keyHex) + '\')">'
                    + '<button class="compare-pill-handle" title="Drag to reorder">::</button>'
                    + '<div class="compare-pill-main">'
                    + '<div class="compare-pill-name">' + esc(item.name) + '</div>'
                    + '<div class="compare-pill-key">' + esc(keyHex) + (item.ts ? ' // ' + esc(fmtRelativeTs(item.ts)) : '') + '</div>'
                    + (item.loading ? '<div class="compare-pill-status">loading metadata...</div>' : '')
                    + '</div>'
                    + '<button class="compare-pill-pin' + (baseline ? ' active' : '') + '" onclick="setCompareBaseline(\'' + esc(keyHex) + '\')" title="Set baseline">B</button>'
                    + '<button class="compare-pill-remove" onclick="removeCompareKey(\'' + esc(keyHex) + '\')">x</button>'
                    + '</div>';
            }).join('');
            persistCompareState();
        }

        function setCompareShowAll(next) {
            compareShowAll = !!next;
            rerenderCompareDiff();
        }

        function setCompareBaseline(keyHex) {
            compareBaselineKey = keyHex;
            updateCompareTray();
            rerenderCompareDiff();
        }

        function startCompareDrag(keyHex) {
            draggingCompareKey = keyHex;
        }

        function allowCompareDrop(event) {
            event.preventDefault();
        }

        function dropCompareKey(targetKey) {
            if (!draggingCompareKey || draggingCompareKey === targetKey) return;
            const from = compareKeys.indexOf(draggingCompareKey);
            const to = compareKeys.indexOf(targetKey);
            if (from < 0 || to < 0) return;
            const [moved] = compareKeys.splice(from, 1);
            compareKeys.splice(to, 0, moved);
            draggingCompareKey = null;
            updateCompareTray();
            rerenderCompareDiff();
        }

        function saveCompareSet() {
            if (compareKeys.length === 0) return;
            const name = prompt('Save compare set as:', 'set-' + new Date().toISOString().slice(0, 10));
            if (!name) return;
            const sets = loadCompareSets();
            sets[name] = {
                keys: [...compareKeys],
                baseline: compareBaselineKey,
                saved_at: Date.now(),
            };
            storeCompareSets(sets);
            refreshCompareLoadOptions();
        }

        function loadCompareSet(name) {
            if (!name) return;
            const sets = loadCompareSets();
            const set = sets[name];
            if (!set || !Array.isArray(set.keys)) return;
            compareKeys.length = 0;
            set.keys.forEach(k => compareKeys.push(k));
            compareBaselineKey = set.baseline || compareKeys[0] || null;
            updateCompareTray();
            renderResultsList();
            hydrateCompareItems(compareKeys);
        }

        function setCompareMode(next) {
            compareMode = next === 'full' ? 'full' : 'summary';
            rerenderCompareDiff();
        }

        function rerenderCompareDiff() {
            if (currentCompareRecords.length >= 2) {
                el.modalBody.innerHTML = buildStructuredDiff(currentCompareRecords);
            }
        }

        function togglePin(keyHex) {
            if (pinnedKeys.has(keyHex)) pinnedKeys.delete(keyHex);
            else pinnedKeys.add(keyHex);
            renderResultsList();
        }

        function removeCompareKey(keyHex) {
            const idx = compareKeys.indexOf(keyHex);
            if (idx >= 0) {
                compareKeys.splice(idx, 1);
            }
            updateCompareTray();
            renderResultsList();
        }

        function toggleCompareKey(keyHex) {
            const hit = currentHits.find(h => h.key_hex === keyHex);
            if (hit) rememberCompareItem(hit);
            const idx = compareKeys.indexOf(keyHex);
            if (idx >= 0) {
                compareKeys.splice(idx, 1);
            } else {
                compareKeys.push(keyHex);
                if (!compareBaselineKey) compareBaselineKey = keyHex;
            }
            updateCompareTray();
            renderResultsList();
        }

        function clearCompareKeys() {
            compareKeys.length = 0;
            compareBaselineKey = null;
            updateCompareTray();
            renderResultsList();
        }

        function openCompareModal() {
            if (compareKeys.length < 2) return;
            currentDetailData = null;
            currentDetailKeyHex = null;
            currentCompareRecords = [];
            pendingDetailSection = null;
            syncHashWithUi();
            el.modalKey.textContent = compareKeys.length + ' FUNCTIONS';
            el.modalBody.innerHTML = '<div class="detail-loading">&gt;&gt;&gt; LOADING COMPARISON...</div>';
            el.detailModal.classList.add('active');
            document.body.style.overflow = 'hidden';

            Promise.all(compareKeys.map(k => fetch('/api/function/' + encodeURIComponent(k)).then(r => r.json())))
                .then(records => {
                    records.forEach(rec => {
                        compareItems.set(rec.key_hex, {
                            key_hex: rec.key_hex,
                            name: rec.name,
                            ts: rec.ts || 0,
                        });
                    });
                    updateCompareTray();
                    currentCompareRecords = records;
                    rerenderCompareDiff();
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

        function setActiveDetailNav(id, updateUrl = true) {
            currentDetailSection = id || null;
            document.querySelectorAll('.detail-nav button').forEach(btn => {
                btn.classList.toggle('active', btn.dataset.target === id);
            });
            if (updateUrl) syncHashWithUi();
        }

        function activateDetailSection(id, updateUrl = true, smooth = true) {
            if (!id) return;
            const node = document.getElementById(id);
            if (node) {
                node.scrollIntoView({ behavior: smooth ? 'smooth' : 'auto', block: 'start' });
            }
            setActiveDetailNav(id, updateUrl);
        }

        function syncDetailSectionFromScroll() {
            if (!el.detailModal.classList.contains('active') || !currentDetailKeyHex) return;
            const anchors = Array.from(el.modalBody.querySelectorAll('.detail-anchor[id]'));
            if (!anchors.length) return;
            const containerTop = el.modalBody.getBoundingClientRect().top;
            let bestId = anchors[0].id;
            let bestDist = Number.POSITIVE_INFINITY;
            anchors.forEach(node => {
                const dist = Math.abs(node.getBoundingClientRect().top - containerTop - 18);
                if (dist < bestDist) {
                    bestDist = dist;
                    bestId = node.id;
                }
            });
            if (bestId && bestId !== currentDetailSection) {
                setActiveDetailNav(bestId, true);
            }
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

        function renderControlFlowMetadata(cf) {
            const ctx = buildControlFlowContext(cf);
            const switches = ctx.switches;
            const tables = ctx.tables;
            if (switches.length === 0 && tables.length === 0) {
                return '<div class="metadata-empty">No switch or jumptable annotations</div>';
            }

            function summarizeRelation(ref) {
                if (ref.source_role === 'default') return 'Default arm';
                if (ref.source_role === 'case' && ref.case_labels && ref.case_labels.length) {
                    return ref.case_labels.length + ' case bucket' + (ref.case_labels.length === 1 ? '' : 's');
                }
                return 'Entry site';
            }

            const switchLinks = ctx.switchLinks;
            const tableSwitchCounts = ctx.tableSwitchCounts;
            const groupedSwitches = ctx.groupedSwitches;
            const controlFlowId = ctx.controlFlowId;

            function renderCopyButton(label, value) {
                return '<button class="controlflow-toggle" onclick="event.stopPropagation();copyText(\'' + esc(value) + '\')">' + esc(label) + '</button>';
            }

            function renderCaseChip(label, groupId = null) {
                const active = selectedControlFlowCase === label;
                const cls = 'case-chip' + (label === 'default' ? ' default' : '') + (active ? ' active' : '');
                if (!groupId) return '<span class="' + cls + '">' + esc(label) + '</span>';
                return '<button class="' + cls + '" onclick="event.stopPropagation();setControlFlowCase(\'' + esc(groupId) + '\', \'' + esc(label) + '\')">' + esc(label) + '</button>';
            }

            let html = '';
            html += '<div class="controlflow-legend">';
            html += '<span class="frame-chip">entry</span><span class="frame-chip">case</span><span class="frame-chip warn">default</span><span class="comment-kind">REG</span><span class="comment-kind repeatable">RPT</span>';
            html += '</div>';
            html += '<div class="controlflow-toolbar">';
            html += '<div class="controlflow-toolbar-summary">';
            html += '<span class="frame-chip">' + esc(String(groupedSwitches.size)) + ' groups</span>';
            html += '<span class="frame-chip">' + esc(String(switches.length)) + ' switch sites</span>';
            html += '<span class="frame-chip">' + esc(String(tables.length)) + ' jump tables</span>';
            if (selectedControlFlowGroup) html += '<span class="controlflow-focus-note">selection ' + esc(selectedControlFlowGroup.replace(/^grp:/, '')) + '</span>';
            if (selectedControlFlowCase) html += '<span class="controlflow-active-filter">' + renderCaseChip(selectedControlFlowCase, selectedControlFlowGroup) + '<button class="controlflow-toggle" onclick="event.stopPropagation();clearControlFlowCase()">Clear Case</button></span>';
            html += '</div>';
            html += '<div class="controlflow-toolbar-actions">';
            html += '<button class="controlflow-toggle" onclick="event.stopPropagation();toggleControlFlowFocusMode()">' + (controlFlowFocusMode ? 'Exit Focus Mode' : 'Focus Selection') + '</button>';
            html += '<button class="controlflow-toggle" onclick="event.stopPropagation();clearControlFlowSelection()">Clear</button>';
            html += '</div></div>';
            if (cf.dominant) {
                html += '<div class="controlflow-hero">';
                html += '<div class="controlflow-hero-title">Dominant Switch Cluster</div>';
                html += '<div class="controlflow-hero-main">';
                html += '<div class="controlflow-hero-addr">' + esc(cf.dominant.addr) + '</div>';
                html += '<div class="controlflow-hero-stats">';
                html += '<span class="frame-chip warn">' + esc(String(cf.dominant.ref_count)) + ' grouped refs</span>';
                html += '<span class="frame-chip warn">' + esc(String(cf.dominant.case_count)) + ' cases</span>';
                cf.dominant.labels.forEach(label => {
                    html += renderCaseChip(label, 'grp:' + cf.dominant.addr);
                });
                html += '</div></div></div>';
            }

            if (groupedSwitches.size > 1 || tables.length > 1) {
                html += '<div class="controlflow-matrix">';
                html += '<div class="controlflow-matrix-row"><div class="controlflow-matrix-cell"><div class="controlflow-matrix-label">Switch Groups</div></div><div class="controlflow-matrix-cell"><div class="controlflow-matrix-value">' + esc(String(groupedSwitches.size)) + '</div></div></div>';
                html += '<div class="controlflow-matrix-row"><div class="controlflow-matrix-cell"><div class="controlflow-matrix-label">Jump Tables</div></div><div class="controlflow-matrix-cell"><div class="controlflow-matrix-value">' + esc(String(tables.length)) + '</div></div></div>';
                Array.from(groupedSwitches.entries()).forEach(([addr, group], idx) => {
                    const label = addr === '__unlinked__' ? 'Unlinked switches' : ('Group ' + (idx + 1));
                    const value = addr === '__unlinked__'
                        ? (group.length + ' switch sites')
                        : (addr + ' // ' + group.length + ' switch sites');
                    const groupId = 'grp:' + addr;
                    html += '<div class="controlflow-matrix-row' + (selectedControlFlowGroup === groupId ? ' active' : '') + '" onclick="setControlFlowGroup(\'' + groupId + '\')"><div class="controlflow-matrix-cell"><div class="controlflow-matrix-label">' + esc(label) + '</div></div><div class="controlflow-matrix-cell"><div class="controlflow-matrix-value">' + esc(value) + '</div></div></div>';
                });
                html += '</div>';
            }

            html += '<div class="controlflow-grid">';
            html += '<div class="controlflow-panel"><div class="detail-label">Switch Sites</div><div class="controlflow-stack">';
            if (switches.length === 0) {
                html += '<div class="metadata-empty">No explicit switch comments</div>';
            } else {
                Array.from(groupedSwitches.entries()).forEach(([addr, group], groupIdx) => {
                    const groupId = 'swgrp-' + groupIdx;
                    const filterId = 'grp:' + addr;
                    const linkedTable = addr === '__unlinked__' ? null : tables.find(jt => jt.addr === addr);
                    if (controlFlowFocusMode && selectedControlFlowGroup && selectedControlFlowGroup !== filterId) return;
                    const collapsed = collapsedSwitchGroups.has(groupId);
                    const dimmed = selectedControlFlowGroup && selectedControlFlowGroup !== filterId;
                    html += '<div class="switch-group' + (collapsed ? ' collapsed' : '') + (dimmed ? ' dimmed' : '') + '">';
                    html += '<div class="switch-group-head" onclick="toggleSwitchGroup(\'' + groupId + '\')">';
                    html += '<span class="switch-group-title">' + (addr === '__unlinked__' ? 'Unlinked Switches' : ('Switch Cluster ' + (groupIdx + 1))) + '</span>';
                    html += '<span class="switch-meta">' + esc(String(group.length)) + ' sites' + (addr !== '__unlinked__' ? (' // ' + addr) : '') + '</span>';
                    html += '</div>';
                    if (linkedTable) {
                        html += renderCompactControlFlowStrip(linkedTable.coverage_runs || linkedTable.all_case_labels || [], [
                            { label: String(linkedTable.case_count || 0) + ' cases' },
                            { label: String(linkedTable.refs.length || 0) + ' refs' },
                            { label: linkedTable.has_default ? 'default path' : 'no default', warn: !!linkedTable.has_default },
                            { label: linkedTable.sparse ? 'sparse' : 'dense', warn: !!linkedTable.sparse },
                        ], filterId);
                    } else {
                        html += renderCompactControlFlowStrip([], [
                            { label: String(group.length) + ' sites' },
                            { label: 'unlinked', warn: true },
                        ], filterId);
                    }
                    html += '<div class="switch-group-body">';
                    group.forEach(sw => {
                        const linkAddr = addr === '__unlinked__' ? null : addr;
                        const rowId = controlFlowId(sw.kind, sw.fchunk_nr, sw.fchunk_off);
                        html += '<div class="switch-card' + (linkAddr ? ' linked' : '') + (selectedControlFlowRow === rowId ? ' active' : '') + '" data-controlflow-id="' + rowId + '" onmouseenter="hoverControlFlowLink(\'' + rowId + '\')" onmouseleave="clearControlFlowHover()" onclick="selectControlFlowRow(\'' + rowId + '\', \'' + filterId + '\')">';
                        html += '<div class="switch-card-head"><span class="switch-title">' + esc(sw.kind) + ' switch</span><span class="switch-meta">chunk ' + esc(String(sw.fchunk_nr)) + ' @ ' + esc(fmtHex(sw.fchunk_off)) + '</span></div>';
                        html += '<div class="switch-desc">' + esc(sw.description) + '</div>';
                        html += '<div class="switch-summary"><span class="frame-chip">' + (sw.description.includes('jump') ? 'jump site' : 'case site') + '</span></div>';
                        if (linkAddr) {
                            html += '<div class="switch-links"><span class="frame-chip">table ' + esc(linkAddr) + '</span><button class="controlflow-toggle" onclick="event.stopPropagation();jumpToControlFlowTable(\'' + esc(linkAddr) + '\')">Open Table</button></div>';
                        }
                        html += '</div>';
                    });
                    html += '</div></div>';
                });
            }
            html += '</div></div>';

            html += '<div class="controlflow-panel"><div class="detail-label">Jump Tables</div><div class="controlflow-stack">';
            if (tables.length === 0) {
                html += '<div class="metadata-empty">No jumptable comments</div>';
            } else {
                tables.forEach(jt => {
                    if (controlFlowFocusMode && selectedControlFlowGroup && selectedControlFlowGroup !== ('grp:' + jt.addr)) return;
                    const expanded = expandedJumpTables.has(jt.addr);
                    const filteredRefs = selectedControlFlowCase && selectedControlFlowGroup === ('grp:' + jt.addr)
                        ? jt.refs.filter(ref => controlFlowCaseMatches(ref, selectedControlFlowCase))
                        : jt.refs;
                    const visibleRefs = expanded ? filteredRefs : filteredRefs.slice(0, 6);
                    const dimmed = selectedControlFlowGroup && selectedControlFlowGroup !== ('grp:' + jt.addr);
                    html += '<div class="jumptable-card' + (dimmed ? ' dimmed' : '') + '" id="jt-' + esc(jt.addr) + '">';
                    html += '<div class="jumptable-head">';
                    html += '<div class="jumptable-title">' + esc(jt.addr) + '</div>';
                    html += '<div class="jumptable-badges">';
                    html += '<span class="frame-chip">' + esc(String(jt.refs.length)) + ' refs</span>';
                    html += '<span class="frame-chip">' + esc(String(jt.case_count)) + ' cases</span>';
                    if (tableSwitchCounts.get(jt.addr)) html += '<span class="frame-chip">' + esc(String(tableSwitchCounts.get(jt.addr))) + ' linked switches</span>';
                    if (jt.sparse) html += '<span class="frame-chip warn">sparse</span>';
                    if (jt.has_default) html += '<span class="frame-chip warn">default case</span>';
                    html += '</div></div>';
                    html += '<div class="controlflow-actions">' + renderCopyButton('Copy Addr', jt.addr) + renderCopyButton('Copy Cases', (jt.all_case_labels || []).join(', ')) + '<button class="controlflow-toggle" onclick="event.stopPropagation();openAllJumpRefs(\'' + esc(jt.addr) + '\')">Open All Refs</button></div>';
                    html += '<div class="jumptable-coverage">';
                    html += '<div class="detail-label" style="margin:0;">Case Coverage</div>';
                    if (jt.coverage_runs && jt.coverage_runs.length > 0) {
                        html += '<div class="coverage-meta">' + jt.coverage_runs.map(label => renderCaseChip(label, 'grp:' + jt.addr)).join('') + '</div>';
                        html += '<div class="jumptable-coverage-strip">';
                        const bins = jt.coverage_runs.slice(0, 24);
                        bins.forEach(label => {
                            html += '<div class="coverage-bin fill' + (label === 'default' ? ' default' : '') + (selectedControlFlowCase === label ? ' active' : '') + '" title="' + esc(label) + '"></div>';
                        });
                        for (let i = bins.length; i < 24; i++) {
                            html += '<div class="coverage-bin"></div>';
                        }
                        html += '</div>';
                    } else {
                        html += '<div class="metadata-empty">No parsed case intervals</div>';
                    }
                    html += '</div>';
                    if (jt.all_case_labels && jt.all_case_labels.length > 0) {
                        html += '<div class="jumptable-cluster-note">Cluster cases</div>';
                        html += '<div class="jumptable-case-strip" style="padding:0 12px 8px;">' + jt.all_case_labels.map(label => renderCaseChip(label, 'grp:' + jt.addr)).join('') + '</div>';
                    }
                    html += '<div class="jumptable-ref-list">';
                    visibleRefs.forEach(ref => {
                        const rowId = controlFlowId(ref.kind, ref.fchunk_nr, ref.fchunk_off);
                        html += '<div class="jumptable-ref' + (selectedControlFlowRow === rowId ? ' active' : '') + '" data-controlflow-id="' + rowId + '" onmouseenter="hoverControlFlowLink(\'' + rowId + '\')" onmouseleave="clearControlFlowHover()" onclick="selectControlFlowRow(\'' + rowId + '\', \'' + ('grp:' + jt.addr) + '\')">';
                        html += '<div class="jumptable-ref-meta">' + esc(ref.kind) + '<br>chunk ' + esc(String(ref.fchunk_nr)) + '<br>@ <a href="javascript:void(0)" onclick="event.stopPropagation();focusCommentRow(&quot;' + rowId + '&quot;, null, true);activateDetailSection(&quot;section-comments&quot;);" style="color:var(--accent);text-decoration:none;">' + esc(fmtHex(ref.fchunk_off)) + '</a></div>';
                        html += '<div class="jumptable-ref-body"><div class="relation-summary"><span class="frame-chip">' + esc(ref.source_role) + '</span><span class="frame-chip">' + esc(summarizeRelation(ref)) + '</span></div>';
                        if (ref.case_labels && ref.case_labels.length > 0) {
                            html += '<div class="jumptable-case-strip">' + ref.case_labels.map(label => renderCaseChip(label, 'grp:' + jt.addr)).join('') + '</div>';
                        }
                        if (ref.lane_size && ref.lane_size > 1) {
                            html += '<div class="jumptable-cluster-note">cluster lane x' + esc(String(ref.lane_size)) + '</div>';
                        }
                        html += '<div class="relation-detail">' + esc(ref.kind) + ' source at chunk ' + esc(String(ref.fchunk_nr)) + ' offset ' + esc(fmtHex(ref.fchunk_off)) + '</div>';
                        html += '</div>';
                        html += '</div>';
                    });
                    if (visibleRefs.length === 0) {
                        html += '<div class="metadata-empty" style="padding:10px 12px;">No refs for selected case bin</div>';
                    }
                    html += '</div>';
                    if (filteredRefs.length > 6) {
                        html += '<div class="jumptable-more"><button class="controlflow-toggle" onclick="event.stopPropagation();toggleJumpTableExpand(&quot;' + esc(jt.addr) + '&quot;)">' + (expanded ? 'Show Less' : ('Show All ' + filteredRefs.length + ' Refs')) + '</button></div>';
                    }
                    html += '<div class="jumptable-graph">';
                    html += '<div class="jumptable-graph-node root"><div class="jumptable-graph-label">Jump Table</div><div class="jumptable-graph-value">' + esc(jt.addr) + '</div></div>';
                    html += '<div class="jumptable-graph-edge">';
                    filteredRefs.slice(0, 8).forEach(ref => {
                        const isActive = selectedControlFlowRow === controlFlowId(ref.kind, ref.fchunk_nr, ref.fchunk_off);
                        html += '<div class="jumptable-graph-node' + (isActive ? ' active' : '') + '"><div class="jumptable-graph-label">' + esc(ref.kind) + ' source</div><div class="jumptable-graph-value">chunk ' + esc(String(ref.fchunk_nr)) + ' @ ' + esc(fmtHex(ref.fchunk_off)) + (ref.case_labels && ref.case_labels.length ? ' // ' + esc(ref.case_labels.join(', ')) : '') + '</div><div class="jumptable-graph-badges"><span class="frame-chip">' + esc(ref.source_role) + '</span>' + (ref.is_default ? '<span class="frame-chip warn">default</span>' : '') + (ref.lane_size && ref.lane_size > 1 ? '<span class="frame-chip">lane x' + esc(String(ref.lane_size)) + '</span>' : '') + (ref.case_labels && ref.case_labels[0] ? renderCaseChip(ref.case_labels[0], 'grp:' + jt.addr) : '') + '</div></div>';
                    });
                    if (filteredRefs.length > 8) {
                        html += '<div class="jumptable-graph-node"><div class="jumptable-graph-value">+' + esc(String(filteredRefs.length - 8)) + ' more refs</div></div>';
                    }
                    html += '</div></div></div>';
                });
            }
            html += '</div></div>';
            html += '</div>';
            return html;
        }

        function normalizeFrameMembers(fd) {
            const members = fd && Array.isArray(fd.members) ? fd.members : [];
            return [...members]
                .map((m, i) => ({
                    key: ((m.offset ?? 'na') + ':' + (m.name || ('#' + i))),
                    name: m.name || ('member_' + i),
                    offset: m.offset ?? null,
                    size: m.nbytes ?? null,
                    type: m.tinfo && m.tinfo.declaration ? m.tinfo.declaration : '-',
                    cmt: m.cmt || '',
                    rptcmt: m.rptcmt || '',
                }))
                .sort((a, b) => {
                    const ao = a.offset === null ? Number.MAX_SAFE_INTEGER : Number(a.offset);
                    const bo = b.offset === null ? Number.MAX_SAFE_INTEGER : Number(b.offset);
                    if (ao !== bo) return ao - bo;
                    return a.name.localeCompare(b.name);
                });
        }

        function normalizeCommentEvents(metadata) {
            const reg = Array.isArray(metadata && metadata.insn_cmts) ? metadata.insn_cmts : [];
            const rpt = Array.isArray(metadata && metadata.rpt_insn_cmts) ? metadata.rpt_insn_cmts : [];
            const events = [];
            reg.forEach(c => events.push({ key: 'reg:' + c.fchunk_nr + ':' + c.fchunk_off + ':' + c.cmt, kind: 'REG', chunk: c.fchunk_nr, off: c.fchunk_off, cmt: c.cmt }));
            rpt.forEach(c => events.push({ key: 'rpt:' + c.fchunk_nr + ':' + c.fchunk_off + ':' + c.cmt, kind: 'RPT', chunk: c.fchunk_nr, off: c.fchunk_off, cmt: c.cmt }));
            return events.sort((a, b) => a.chunk - b.chunk || a.off - b.off || a.kind.localeCompare(b.kind));
        }

        function renderCompareSubsection(title, rows) {
            if (!rows.length) return '';
            return '<div class="compare-subsection"><div class="compare-subtitle">' + esc(title) + '</div>' + rows.join('') + '</div>';
        }

        function multiJump(section) {
            return currentCompareRecords.map(rec => ({ key: rec.key_hex, section }));
        }

        function renderMatrixRow(label, values, options = {}) {
            const mode = options.mode || 'generic';
            const normalized = values.map(v => String(v || '-'));
            const baseline = normalized[0] || '-';
            const unchanged = normalized.every(v => v === baseline);
            const jumps = options.jumps || [];
            const classes = ['compare-row'];
            if (!compareShowAll && unchanged) classes.push('unchanged');
            let html = '<div class="' + classes.join(' ') + '">';
            html += '<div class="compare-label">' + esc(label) + '</div>';
            normalized.forEach((value, idx) => {
                const diff = idx > 0 && value !== baseline;
                const rendered = idx === 0 || !diff ? esc(value) : diffTokenHtml(baseline, value, mode).rightHtml;
                const jump = jumps[idx];
                const click = jump ? ' onclick="event.stopPropagation();showFunctionDetail(\'' + esc(jump.key) + '\', \'' + esc(jump.section) + '\')"' : '';
                html += '<div class="compare-cell' + (diff ? ' diff' : '') + (jump ? ' jumpable' : '') + '"' + click + '>' + rendered + '</div>';
            });
            html += '</div>';
            return html;
        }

        function renderSignatureDiff(records) {
            const parsed = records.map(r => parseDecodedSignature((summaryFromMetadata(r).typeDecl || '')));
            const typeDecls = records.map(r => summaryFromMetadata(r).typeDecl || '-');
            const jumps = multiJump('section-type');
            const rows = [
                renderMatrixRow('Declaration', typeDecls, { mode: 'type', jumps }),
                renderMatrixRow('Return Type', parsed.map(p => p ? p.returnType : '-'), { mode: 'type', jumps }),
                renderMatrixRow('Call Conv', parsed.map(p => p ? (p.cc || 'default') : '-'), { jumps }),
                renderMatrixRow('Return Loc', parsed.map(p => p ? (p.retLoc || '-') : '-'), { jumps }),
            ];
            if (compareMode === 'full') {
                const maxArgs = Math.max(...parsed.map(p => p ? p.args.length : 0), 0);
                for (let i = 0; i < maxArgs; i++) {
                    rows.push(renderMatrixRow('Arg ' + i, parsed.map(p => p && p.args[i] ? p.args[i] : '-'), { mode: 'type', jumps }));
                }
            }
            return renderCompareSection('Type Signature', rows);
        }

        function renderFrameMemberDiff(records) {
            const frames = records.map(r => r.metadata && r.metadata.frame_desc ? r.metadata.frame_desc : {});
            const normalized = frames.map(fd => normalizeFrameMembers(fd));
            const rowKeys = [];
            const rowMap = new Map();

            normalized.forEach(members => {
                members.forEach(m => {
                    const key = (m.offset !== null ? 'off:' + m.offset : 'name:' + m.name);
                    if (!rowMap.has(key)) {
                        rowMap.set(key, true);
                        rowKeys.push(key);
                    }
                });
            });

            rowKeys.sort((a, b) => {
                const ao = a.startsWith('off:') ? Number(a.slice(4)) : Number.MAX_SAFE_INTEGER;
                const bo = b.startsWith('off:') ? Number(b.slice(4)) : Number.MAX_SAFE_INTEGER;
                if (ao !== bo) return ao - bo;
                return a.localeCompare(b);
            });

            const jumps = multiJump('section-frame');
            const rows = [
                renderMatrixRow('Members', normalized.map(m => String(m.length)), { jumps }),
                renderMatrixRow('Frame Size', frames.map(fd => fmtHex(fd.frsize)), { jumps }),
                renderMatrixRow('Arg Size', frames.map(fd => fmtHex(fd.argsize)), { jumps }),
                renderMatrixRow('Diagnostics', frames.map(fd => analyzeFrame(fd).map(x => x.label).join(', ') || 'layout coherent'), { jumps }),
            ];

            if (compareMode === 'full') {
                rowKeys.forEach((key, i) => {
                    const vals = normalized.map(members => {
                        const found = members.find(m => (m.offset !== null ? 'off:' + m.offset : 'name:' + m.name) === key)
                            || members.find(m => key.startsWith('off:') && m.offset === Number(key.slice(4)));
                        if (!found) return '-';
                        return (found.offset !== null ? fmtHex(found.offset) : '-') + ' ' + found.name + ' : ' + found.type + (found.size !== null ? ' [' + fmtHex(found.size) + ']' : '') + (found.cmt ? ' // ' + found.cmt : '');
                    });
                    rows.push(renderMatrixRow('Member ' + i, vals, { mode: 'type', jumps }));
                });
            }
            return renderCompareSection('Frame Layout', rows);
        }

        function renderCommentDiff(records) {
            const metas = records.map(r => r.metadata || {});
            const eventsByRecord = metas.map(m => normalizeCommentEvents(m));
            const jumps = multiJump('section-comments');
            const rows = [
                renderMatrixRow('Total Comments', eventsByRecord.map(e => String(e.length)), { jumps }),
                renderMatrixRow('Regular Comment', metas.map(m => m.fcmt || '-'), { mode: 'comment', jumps }),
                renderMatrixRow('Repeatable Comment', metas.map(m => m.frptcmt || '-'), { mode: 'comment', jumps }),
            ];

            if (compareMode === 'full') {
                const eventKeys = [];
                const seen = new Set();
                eventsByRecord.forEach(events => {
                    events.forEach(e => {
                        const key = e.kind + ':' + e.chunk + ':' + e.off;
                        if (!seen.has(key)) {
                            seen.add(key);
                            eventKeys.push(key);
                        }
                    });
                });
                eventKeys.sort((a, b) => {
                    const [ak, ac, ao] = a.split(':');
                    const [bk, bc, bo] = b.split(':');
                    return Number(ac) - Number(bc) || Number(ao) - Number(bo) || ak.localeCompare(bk);
                });

                eventKeys.slice(0, 24).forEach(key => {
                    const [kind, chunk, off] = key.split(':');
                    const vals = eventsByRecord.map(events => {
                        const ev = events.find(e => e.kind === kind && String(e.chunk) === chunk && String(e.off) === off);
                        return ev ? ev.cmt : '-';
                    });
                    rows.push(renderMatrixRow('Chunk ' + chunk + ' @ ' + fmtHex(Number(off)) + ' [' + kind + ']', vals, { mode: 'comment', jumps }));
                });
            }

            return renderCompareSection('Comments', rows);
        }

        function compareValue(a, b) {
            return String(a || '') !== String(b || '');
        }

        function tokenizeForDiff(text, mode = 'generic') {
            const s = String(text || '-');
            if (mode === 'comment') {
                return s.match(/\s+|\w+|[^\w\s]/g) || [s];
            }
            if (mode === 'type') {
                return s.match(/\s+|::|->|=>|@<|>|<|\w+|[^\w\s]/g) || [s];
            }
            return s.match(/\s+|\w+|[^\w\s]/g) || [s];
        }

        function diffTokenHtml(left, right, mode = 'generic') {
            const a = tokenizeForDiff(left, mode);
            const b = tokenizeForDiff(right, mode);
            const m = a.length;
            const n = b.length;
            const dp = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));

            for (let i = m - 1; i >= 0; i--) {
                for (let j = n - 1; j >= 0; j--) {
                    dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
                }
            }

            let i = 0;
            let j = 0;
            let leftHtml = '';
            let rightHtml = '';
            while (i < m && j < n) {
                if (a[i] === b[j]) {
                    const t = esc(a[i]);
                    leftHtml += t;
                    rightHtml += t;
                    i++;
                    j++;
                } else if (dp[i + 1][j] >= dp[i][j + 1]) {
                    leftHtml += '<span class="diff-del">' + esc(a[i]) + '</span>';
                    i++;
                } else {
                    rightHtml += '<span class="diff-add">' + esc(b[j]) + '</span>';
                    j++;
                }
            }
            while (i < m) {
                leftHtml += '<span class="diff-del">' + esc(a[i]) + '</span>';
                i++;
            }
            while (j < n) {
                rightHtml += '<span class="diff-add">' + esc(b[j]) + '</span>';
                j++;
            }

            return { leftHtml, rightHtml };
        }

        function compareRow(label, left, right, options = {}) {
            const diff = compareValue(left, right);
            const mode = options.mode || 'generic';
            const rendered = diff ? diffTokenHtml(left, right, mode) : { leftHtml: esc(String(left || '-')), rightHtml: esc(String(right || '-')) };
            const jumpable = options.leftJump || options.rightJump;
            const classes = ['compare-row'];
            if (jumpable) classes.push('jumpable');
            if (!diff) classes.push('unchanged');
            const leftClick = options.leftJump ? ' onclick="event.stopPropagation();showFunctionDetail(\'' + esc(options.leftJump.key) + '\', \'' + esc(options.leftJump.section) + '\')"' : '';
            const rightClick = options.rightJump ? ' onclick="event.stopPropagation();showFunctionDetail(\'' + esc(options.rightJump.key) + '\', \'' + esc(options.rightJump.section) + '\')"' : '';
            const labelExtra = jumpable ? '<div style="margin-top:4px;font-size:9px;color:var(--text-tertiary);">jump: ' + (options.leftJump ? 'L' : '-') + ' / ' + (options.rightJump ? 'R' : '-') + '</div>' : '';
            return '<div class="' + classes.join(' ') + '">'
                + '<div class="compare-cell' + (diff ? ' diff' : '') + '"' + leftClick + '>' + rendered.leftHtml + '</div>'
                + '<div class="compare-label">' + esc(label) + labelExtra + '</div>'
                + '<div class="compare-cell' + (diff ? ' diff' : '') + '"' + rightClick + '>' + rendered.rightHtml + '</div>'
                + '</div>';
        }

        function renderCompareSection(title, rows) {
            return '<div class="compare-section" style="--compare-cols:' + currentCompareRecords.length + ';"><div class="compare-section-title">' + esc(title) + '</div>' + rows.join('') + '</div>';
        }

        function buildStructuredDiff(records) {
            const ordered = [...records];
            const baselineIndex = compareBaselineKey ? ordered.findIndex(r => r.key_hex === compareBaselineKey) : 0;
            if (baselineIndex > 0) {
                const [baseline] = ordered.splice(baselineIndex, 1);
                ordered.unshift(baseline);
            }
            const summaries = ordered.map(summaryFromMetadata);
            const metas = ordered.map(r => r.metadata || {});
            let html = '<div class="compare-diff' + (compareShowAll ? ' show-all' : '') + '">';
            html += '<div class="compare-toolbar">';
            html += '<div class="compare-toolbar-group">';
            html += '<button class="compare-toggle' + (compareMode === 'summary' ? ' active' : '') + '" onclick="setCompareMode(\'summary\')">Summary</button>';
            html += '<button class="compare-toggle' + (compareMode === 'full' ? ' active' : '') + '" onclick="setCompareMode(\'full\')">Full Diff</button>';
            html += '<button class="compare-toggle' + (compareShowAll ? ' active' : '') + '" onclick="setCompareShowAll(' + (!compareShowAll) + ')">' + (compareShowAll ? 'Hide Unchanged' : 'Show Unchanged') + '</button>';
            html += '</div>';
            html += '<div class="compare-status">' + ordered.length + ' functions // ' + esc(compareMode) + ' mode // baseline first</div>';
            html += '</div>';
            html += '<div class="compare-head" style="--compare-cols:' + ordered.length + ';"><div class="compare-head-cell center">Field</div>';
            ordered.forEach((rec, idx) => {
                html += '<div class="compare-head-cell"><div class="compare-name">' + esc(rec.name) + (idx === 0 ? ' [baseline]' : '') + '</div><div class="compare-key">' + esc(rec.key_hex) + '</div></div>';
            });
            html += '</div>';

            html += renderCompareSection('Identity', [
                renderMatrixRow('Age', ordered.map(r => fmtRelativeTs(r.ts))),
                renderMatrixRow('Data Size', ordered.map(r => fmtBytes(r.data_size || 0))),
                renderMatrixRow('Binary Count', ordered.map(r => String((r.binary_names || []).length))),
                renderMatrixRow('Binaries', ordered.map(r => (r.binary_names || []).join(', '))),
            ]);

            currentCompareRecords = ordered;
            html += renderSignatureDiff(ordered);

            html += renderFrameMemberDiff(ordered);

            html += renderCommentDiff(ordered);

            html += renderCompareSection('Parser', [
                renderMatrixRow('Bytes Parsed', metas.map(m => String(m.bytes_parsed || 0))),
                renderMatrixRow('Raw Size', metas.map(m => fmtBytes(m.raw_size || 0))),
                renderMatrixRow('Error List', metas.map(m => (m.errors || []).join(' | ') || '-'), { mode: 'comment' }),
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

        function renderInstructionCommentTimeline(insnCmts, rptInsnCmts, controlFlow) {
            const events = [];
            const cfCtx = buildControlFlowContext(controlFlow);
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
                ev.controlFlowRowId = cfCtx.controlFlowId(ev.kind, ev.chunk, ev.off);
                ev.controlFlowGroupId = cfCtx.rowToGroup.get(ev.controlFlowRowId) || null;
                if (filterKind !== 'all' && ev.kind !== filterKind) return false;
                if (term && !ev.cmt.toLowerCase().includes(term)) return false;
                if (controlFlowFocusMode && selectedControlFlowGroup) return ev.controlFlowGroupId === selectedControlFlowGroup;
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
                    let markerClick = 'focusCommentRow(\'' + ev.rowId + '\', \'' + ev.markerId + '\', true)';
                    if (ev.controlFlowGroupId) {
                        markerClick = 'activateCommentEvent(\'' + ev.rowId + '\', \'' + ev.markerId + '\', \'' + ev.controlFlowRowId + '\', \'' + ev.controlFlowGroupId + '\', true)';
                    }
                    html += '<div id="' + ev.markerId + '" class="comment-marker' + (ev.kind === 'rpt' ? ' repeatable' : '') + '" style="left:' + left.toFixed(2) + '%;top:' + top + 'px;" title="' + esc(title) + '" onmouseenter="pulseCommentMarker(\'' + ev.markerId + '\')" onclick="' + markerClick + '"></div>';
                });

                html += '</div>';
                html += '<div class="comment-scale"><span>' + fmtHex(minOff) + '</span><span>' + fmtHex(maxOff) + '</span></div>';

                html += '<div class="comment-list">';
                list.forEach(ev => {
                    const dimmed = selectedControlFlowGroup && ev.controlFlowGroupId !== selectedControlFlowGroup;
                    const activeCf = selectedControlFlowRow && ev.controlFlowRowId === selectedControlFlowRow;
                    let click = 'focusCommentRow(\'' + ev.rowId + '\', \'' + ev.markerId + '\', false)';
                    if (ev.controlFlowGroupId) {
                        click = 'activateCommentEvent(\'' + ev.rowId + '\', \'' + ev.markerId + '\', \'' + ev.controlFlowRowId + '\', \'' + ev.controlFlowGroupId + '\', false)';
                    }
                    html += '<div class="comment-item' + (dimmed ? ' dimmed' : '') + (activeCf ? ' active-controlflow' : '') + '" id="' + ev.rowId + '" data-controlflow-id="' + ev.controlFlowRowId + '" onmouseenter="pulseCommentMarker(\'' + ev.markerId + '\');hoverControlFlowLink(\'' + ev.controlFlowRowId + '\')" onmouseleave="clearControlFlowHover()" onclick="' + click + '">';
                    html += '<div class="comment-item-head">';
                    html += '<span class="comment-kind' + (ev.kind === 'rpt' ? ' repeatable' : '') + '">' + (ev.kind === 'rpt' ? 'RPT' : 'REG') + '</span>';
                    html += '<span>' + fmtHex(ev.off) + '</span>';
                    html += '</div>';
                    html += renderCommentText(ev);
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
        let currentDetailKeyHex = null;
        let currentDetailSection = null;
        let detailScrollSyncRaf = null;
        let copiedKeyHex = null;
        let copiedKeyTimer = null;
        let pendingDetailSection = null;
        let currentCompareRecords = [];
        let suppressHashHandler = false;
        const metricAnimationState = new Map();

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
            let row = document.getElementById(rowId);
            if (!row) {
                row = document.querySelector('[data-controlflow-id="' + rowId + '"]');
            }
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

        function activateCommentEvent(rowId, markerId, controlId = null, groupId = null, shouldScroll = false) {
            if (controlId) {
                selectControlFlowRow(controlId, groupId, false);
                setTimeout(() => focusCommentRow(rowId, markerId, shouldScroll), 0);
                return;
            }
            focusCommentRow(rowId, markerId, shouldScroll);
        }

        function toggleCommentChunk(chunkId) {
            if (collapsedCommentChunks.has(chunkId)) collapsedCommentChunks.delete(chunkId);
            else collapsedCommentChunks.add(chunkId);
            if (currentDetailData) renderFunctionDetail(currentDetailData);
        }

        function toggleJumpTableExpand(addr) {
            if (expandedJumpTables.has(addr)) expandedJumpTables.delete(addr);
            else expandedJumpTables.add(addr);
            if (currentDetailData) renderFunctionDetail(currentDetailData);
        }

        function clearControlFlowSelection() {
            selectedControlFlowGroup = null;
            selectedControlFlowRow = null;
            selectedControlFlowCase = null;
            controlFlowFocusMode = false;
            if (currentDetailData) renderFunctionDetail(currentDetailData);
        }

        function selectControlFlowRow(rowId, groupId = null, rerender = true) {
            const prevGroup = selectedControlFlowGroup;
            const sameRow = selectedControlFlowRow === rowId;
            const sameGroup = (groupId || null) === (selectedControlFlowGroup || null);
            if (sameRow && sameGroup) {
                selectedControlFlowRow = null;
                if (!controlFlowFocusMode) selectedControlFlowGroup = groupId || null;
            } else {
                selectedControlFlowRow = rowId;
                if (groupId) selectedControlFlowGroup = groupId;
            }
            if (groupId && prevGroup !== groupId) selectedControlFlowCase = null;
            if (controlFlowFocusMode && !selectedControlFlowGroup) controlFlowFocusMode = false;
            if (rerender && currentDetailData) renderFunctionDetail(currentDetailData);
        }

        function setControlFlowGroup(groupId) {
            const nextGroup = selectedControlFlowGroup === groupId ? null : groupId;
            if (nextGroup !== selectedControlFlowGroup) selectedControlFlowCase = null;
            selectedControlFlowGroup = nextGroup;
            if (!selectedControlFlowGroup) {
                selectedControlFlowRow = null;
                controlFlowFocusMode = false;
            }
            if (currentDetailData) renderFunctionDetail(currentDetailData);
        }

        function setControlFlowCase(groupId, label) {
            if (!groupId || !label) return;
            if (selectedControlFlowGroup !== groupId) {
                selectedControlFlowGroup = groupId;
            }
            selectedControlFlowCase = selectedControlFlowCase === label ? null : label;
            selectedControlFlowRow = null;
            if (currentDetailData) renderFunctionDetail(currentDetailData);
        }

        function clearControlFlowCase() {
            selectedControlFlowCase = null;
            if (currentDetailData) renderFunctionDetail(currentDetailData);
        }

        function toggleControlFlowFocusMode() {
            if (!selectedControlFlowGroup) return;
            controlFlowFocusMode = !controlFlowFocusMode;
            if (currentDetailData) renderFunctionDetail(currentDetailData);
        }

        function toggleSwitchGroup(groupId) {
            if (collapsedSwitchGroups.has(groupId)) collapsedSwitchGroups.delete(groupId);
            else collapsedSwitchGroups.add(groupId);
            if (currentDetailData) renderFunctionDetail(currentDetailData);
        }

        function jumpToControlFlowTable(addr) {
            const node = document.getElementById('jt-' + addr);
            if (node) node.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }

        function openAllJumpRefs(addr) {
            expandedJumpTables.add(addr);
            if (currentDetailData) {
                renderFunctionDetail(currentDetailData);
                setTimeout(() => jumpToControlFlowTable(addr), 0);
            }
        }

        function hoverControlFlowLink(controlId) {
            clearControlFlowHover();
            document.querySelectorAll('[data-controlflow-id="' + controlId + '"]').forEach(node => node.classList.add('linked'));
        }

        function clearControlFlowHover() {
            document.querySelectorAll('.linked').forEach(node => node.classList.remove('linked'));
        }

        function parseControlFlowComment(text) {
            const cmt = String(text || '').trim();
            if (cmt.startsWith('switch ')) {
                return { type: 'switch', summary: cmt, chips: [] };
            }
            if (cmt.startsWith('jumptable ')) {
                const rest = cmt.slice('jumptable '.length);
                const space = rest.indexOf(' ');
                const addr = space >= 0 ? rest.slice(0, space) : rest;
                const rel = space >= 0 ? rest.slice(space + 1).trim() : '';
                const labels = [];
                if (rel.includes('default case')) labels.push('default');
                rel.split(/[,\s]+/).forEach(tok => {
                    if (/^\d+(?:-\d+)?$/.test(tok)) labels.push(tok);
                });
                return { type: 'jumptable', addr, summary: rel || 'entry', chips: labels };
            }
            return null;
        }

        function renderCommentText(ev) {
            const parsed = parseControlFlowComment(ev.cmt);
            if (!parsed) return '<div class="comment-item-text">' + esc(ev.cmt) + '</div>';
            let html = '<div class="comment-item-text controlflow">';
            html += '<div class="comment-flow-main">';
            html += '<span class="frame-chip' + (parsed.type === 'jumptable' ? '' : ' warn') + '">' + esc(parsed.type) + '</span>';
            if (parsed.addr) html += '<span class="frame-chip">' + esc(parsed.addr) + '</span>';
            parsed.chips.slice(0, 12).forEach(label => {
                html += '<span class="case-chip' + (label === 'default' ? ' default' : '') + '">' + esc(label) + '</span>';
            });
            html += '</div>';
            html += '<div class="comment-flow-detail">' + esc(parsed.summary) + '</div>';
            html += '</div>';
            return html;
        }

        function parseHash() {
            const params = new URLSearchParams(window.location.hash.slice(1));
            return {
                q: params.get('q') || '',
                page: parseInt(params.get('page') || '1', 10) || 1,
                f: params.get('f') || '',
                s: params.get('s') || ''
            };
        }

        function updateHash(query, page = 1, functionKey = '', sectionId = '') {
            const params = new URLSearchParams();
            if (query) params.set('q', query);
            if (query && page > 1) params.set('page', String(page));
            if (functionKey) params.set('f', functionKey);
            if (functionKey && sectionId) params.set('s', sectionId);
            const nextHash = params.toString();
            if (!nextHash) {
                history.replaceState(null, '', window.location.pathname);
                return;
            }
            const currentHash = window.location.hash.replace(/^#/, '');
            if (currentHash === nextHash) return;
            suppressHashHandler = true;
            window.location.hash = nextHash;
            setTimeout(() => { suppressHashHandler = false; }, 0);
        }

        function syncHashWithUi() {
            const functionKey = el.detailModal.classList.contains('active') && currentDetailKeyHex ? currentDetailKeyHex : '';
            const sectionId = functionKey ? (currentDetailSection || pendingDetailSection || '') : '';
            updateHash(currentQuery, currentPage, functionKey, sectionId);
        }

        function applyHashState(state) {
            const q = (state && state.q) ? state.q : '';
            const page = state && state.page ? state.page : 1;
            const f = (state && state.f) ? state.f : '';
            const s = (state && state.s) ? state.s : null;

            el.q.value = q;
            if (q) {
                runSearch(q, page, false).then(() => {
                    const needsOpen = f && (!el.detailModal.classList.contains('active') || currentDetailKeyHex !== f || currentCompareRecords.length > 0);
                    if (needsOpen) showFunctionDetail(f, s, false);
                    else if (f && s && currentDetailKeyHex === f && !currentCompareRecords.length) activateDetailSection(s, false, false);
                    else if (!f && el.detailModal.classList.contains('active') && !currentCompareRecords.length) closeDetailModal(false);
                });
                return;
            }

            showDashboard(false);
            if (f && (!el.detailModal.classList.contains('active') || currentDetailKeyHex !== f || currentCompareRecords.length > 0)) {
                showFunctionDetail(f, s, false);
            } else if (f && s && currentDetailKeyHex === f && !currentCompareRecords.length) {
                activateDetailSection(s, false, false);
            } else if (!f && el.detailModal.classList.contains('active') && !currentCompareRecords.length) {
                closeDetailModal(false);
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

                animateMetricValue(el.mIndexed, d.indexed_funcs || 0, fmtWholeAnimated, 1050);
                animateMetricValue(el.mStorage, d.storage_bytes || 0, fmtBytesAnimated, 1100);
                animateMetricValue(el.mSearchDocs, d.search_docs || 0, fmtWholeAnimated, 1000);
                animateMetricValue(el.mBinaries, d.unique_binaries || 0, fmtWholeAnimated, 950);
                animateMetricValue(el.mQueried, d.queried_funcs || 0, fmtWholeAnimated, 1000);
                animateMetricValue(el.mRpc, d.active_connections || 0, fmtWholeAnimated, 650);
                animateMetricValue(el.mUpstream, d.upstream_requests || 0, fmtWholeAnimated, 900);
                animateMetricValue(el.mFetched, d.upstream_fetched || 0, fmtWholeAnimated, 900);
                animateMetricValue(el.mNew, d.new_funcs || 0, fmtWholeAnimated, 850);
                animateMetricValue(el.mPulls, d.pulls || 0, fmtWholeAnimated, 850);
                animateMetricValue(el.mPushes, d.pushes || 0, fmtWholeAnimated, 850);
                animateMetricValue(el.mScoring, d.scoring_batches || 0, fmtWholeAnimated, 900);
                animateMetricValue(el.mErrors, d.errors || 0, fmtWholeAnimated, 700);
                animateMetricValue(el.mTimeouts, d.timeouts || 0, fmtWholeAnimated, 700);
                animateMetricValue(el.mRejects, d.decoder_rejects || 0, fmtWholeAnimated, 700);
                animateMetricValue(el.mAppend, d.append_failures || 0, fmtWholeAnimated, 700);
                animateMetricValue(el.mOverflow, d.index_overflows || 0, fmtWholeAnimated, 700);
                animateMetricValue(el.mUpErr, d.upstream_errors || 0, fmtWholeAnimated, 700);
                animateMetricValue(el.mTotalRec, d.total_records || 0, fmtWholeAnimated, 1100);
                animateMetricValue(el.mVconsidered, d.scoring_versions_considered || 0, fmtWholeAnimated, 1000);
                animateMetricValue(el.mFallback, d.scoring_fallback_latest || 0, fmtWholeAnimated, 900);

                animateMetricValue(el.protoV5, d.lumina_v5p || 0, fmtWholeAnimated, 650);
                animateMetricValue(el.protoV0, d.lumina_v0_4 || 0, fmtWholeAnimated, 650);

                setRateText(el.rateQps, d.queried_funcs, prev && prev.queried_funcs, dtSec);
                setRateText(el.ratePulls, d.pulls, prev && prev.pulls, dtSec);
                setRateText(el.ratePushes, d.pushes, prev && prev.pushes, dtSec);
                setRateText(el.rateTotalRec, d.total_records, prev && prev.total_records, dtSec);
                setRateText(el.rateVconsidered, d.scoring_versions_considered, prev && prev.scoring_versions_considered, dtSec);
                setRateText(el.rateFallback, d.scoring_fallback_latest, prev && prev.scoring_fallback_latest, dtSec);

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

        function showDashboard(updateUrl = true) {
            el.dashboard.classList.remove('hidden');
            el.secondary.classList.remove('hidden');
            el.results.classList.remove('active');
            el.comparePanel.classList.add('hidden');
            el.pagination.innerHTML = '';
            currentPage = 1;
            currentQuery = '';
            currentHits = [];
            selectedResultIndex = -1;
            openPreviewKey = null;
            if (updateUrl) syncHashWithUi();
        }

        async function runSearch(query, page = 1, updateUrl = true) {
            query = query.trim();
            if (!query) { showDashboard(updateUrl); return; }

            currentQuery = query;
            currentPage = page;

            el.dashboard.classList.add('hidden');
            el.secondary.classList.add('hidden');
            el.results.classList.add('active');
            el.comparePanel.classList.remove('hidden');
            el.resultsQuery.textContent = query;
            el.resultsList.innerHTML = '<div class="state-message"><div class="icon">&gt;&gt;&gt;</div><h3>QUERYING INDEX</h3><p>Processing request...</p></div>';
            el.pagination.innerHTML = '';

            if (updateUrl) updateHash(query, page, currentDetailKeyHex || '');

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
        el.compareSave.addEventListener('click', saveCompareSet);
        el.compareExport.addEventListener('click', exportCompareSet);
        el.compareImport.addEventListener('click', () => el.compareImportFile.click());
        el.compareLoad.addEventListener('change', e => loadCompareSet(e.target.value));
        el.compareImportFile.addEventListener('change', async e => {
            const file = e.target.files && e.target.files[0];
            if (!file) return;
            try {
                const text = await file.text();
                importCompareSetFromText(text);
            } catch (err) {
                alert('Failed to import compare set: ' + (err.message || String(err)));
            } finally {
                e.target.value = '';
            }
        });
        window.addEventListener('hashchange', () => {
            if (suppressHashHandler) return;
            applyHashState(parseHash());
        });

        updateTime();
        setInterval(updateTime, 1000);
        fetchMetrics();
        setInterval(fetchMetrics, 5000);
        restoreCompareState();
        updateCompareTray();
        hydrateCompareItems(compareKeys);
        refreshCompareLoadOptions();
        el.resultsSort.value = currentSort;

        applyHashState(parseHash());

        // ═══════════════════════════════════════════════════════════════
        // FUNCTION DETAIL MODAL
        // ═══════════════════════════════════════════════════════════════

        function showFunctionDetail(keyHex, sectionId = null, updateUrl = true) {
            currentDetailData = null;
            currentDetailKeyHex = keyHex;
            currentCompareRecords = [];
            pendingDetailSection = sectionId;
            selectedControlFlowGroup = null;
            selectedControlFlowRow = null;
            selectedControlFlowCase = null;
            controlFlowFocusMode = false;
            currentDetailSection = sectionId || null;
            if (updateUrl) syncHashWithUi();
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

        function closeDetailModal(updateUrl = true) {
            el.detailModal.classList.remove('active');
            document.body.style.overflow = '';
            currentDetailData = null;
            currentDetailKeyHex = null;
            currentCompareRecords = [];
            pendingDetailSection = null;
            selectedControlFlowGroup = null;
            selectedControlFlowRow = null;
            selectedControlFlowCase = null;
            controlFlowFocusMode = false;
            currentDetailSection = null;
            if (updateUrl) syncHashWithUi();
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

        el.modalBody.addEventListener('scroll', () => {
            if (detailScrollSyncRaf) cancelAnimationFrame(detailScrollSyncRaf);
            detailScrollSyncRaf = requestAnimationFrame(() => {
                detailScrollSyncRaf = null;
                syncDetailSectionFromScroll();
            });
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
            currentDetailKeyHex = data.key_hex || currentDetailKeyHex;

            const m = data.metadata || {};
            const parseBadge = (m.errors && m.errors.length > 0) ? 'PARTIAL' : 'PARSED';

            const sections = [
                { id: 'section-overview', label: 'Overview' },
            ];
            if (m.fcmt || m.frptcmt || m.vd_elapsed !== null) sections.push({ id: 'section-attrs', label: 'Attributes' });
            if (m.type_parts) sections.push({ id: 'section-type', label: 'Type' });
            if (m.frame_desc) sections.push({ id: 'section-frame', label: 'Frame' });
            if (m.control_flow && ((m.control_flow.switches || []).length > 0 || (m.control_flow.jumptables || []).length > 0)) sections.push({ id: 'section-controlflow', label: 'Switches' });
            if (((m.insn_cmts || []).length + (m.rpt_insn_cmts || []).length) > 0) sections.push({ id: 'section-comments', label: 'Comments' });
            if ((m.errors || []).length > 0) sections.push({ id: 'section-errors', label: 'Errors' });

            let html = '<div class="detail-layout">';
            html += '<div class="detail-nav">';
            const activeSectionId = pendingDetailSection || currentDetailSection || sections[0].id;
            sections.forEach((s, i) => {
                html += '<button data-target="' + s.id + '" class="' + (s.id === activeSectionId || (i === 0 && !activeSectionId) ? 'active' : '') + '" onclick="activateDetailSection(\'' + s.id + '\');">' + esc(s.label) + '</button>';
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

                if (m.control_flow && ((m.control_flow.switches || []).length > 0 || (m.control_flow.jumptables || []).length > 0)) {
                    html += '<div class="metadata-section detail-anchor" id="section-controlflow"><div class="metadata-header"><span>Switch / Jumptable Analysis</span><span class="badge nominal">CONTROL FLOW</span></div><div class="metadata-content">';
                    html += renderControlFlowMetadata(m.control_flow);
                    html += '</div></div>';
                }

                // Instruction Comments Timeline
                const regCount = Array.isArray(m.insn_cmts) ? m.insn_cmts.length : 0;
                const rptCount = Array.isArray(m.rpt_insn_cmts) ? m.rpt_insn_cmts.length : 0;
                const totalCommentCount = regCount + rptCount;
                if (totalCommentCount > 0) {
                    html += '<div class="metadata-section detail-anchor" id="section-comments"><div class="metadata-header"><span>Instruction Comment Timeline</span><span class="badge">' + totalCommentCount + '</span></div><div class="metadata-content">';
                    html += renderInstructionCommentTimeline(m.insn_cmts, m.rpt_insn_cmts, m.control_flow);
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
            if (pendingDetailSection) {
                activateDetailSection(pendingDetailSection, false, false);
                pendingDetailSection = null;
            } else if (!currentDetailSection) {
                currentDetailSection = 'section-overview';
                setActiveDetailNav(currentDetailSection, false);
            } else {
                setActiveDetailNav(currentDetailSection, false);
            }
        }
    </script>
</body>
</html>
"#;
