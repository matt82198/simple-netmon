# vigil — Logo Concept & Brand Assets

## Project: vigil
**Tagline**: Host-based AI-attacker detector  
**Purpose**: Real-time anomaly detection for OAuth 2.0 chaining and lateral threat movement

---

## 1. ASCII Art Logo

### Variant A — Lighthouse / Beacon (RECOMMENDED)
```
  /\
 /  \
 ||||
 ||||
 ||||
  ||
 /  \
```
**Dimensions**: 7 lines × 6 chars wide  
**Concept**: A beacon sweeping upward, watching the sky. Minimal, vertical, evokes "sentinel on alert."  
**Terminal render**: Clean in monospace; the repeated pipes suggest active scanning.

---

### Variant B — Watchtower
```
+-----+
|  O  |
| --- |
|  V  |
+-----+
```
**Dimensions**: 5 lines × 7 chars wide  
**Concept**: Eye over an arrow (downward threat), enclosed in watchtower walls.  
**Terminal render**: Boxed, stable, fortress-like. O = eye, V = focused downward.

---

### Variant C — Radar Sweep
```
    *
  *   *
 *     *
  *   *
    *
```
**Dimensions**: 5 lines × 9 chars wide  
**Concept**: Concentric ping/pulse, like radar scanning outward. Represents continuous monitoring.  
**Terminal render**: Abstract but readable as "active detection."

---

## RECOMMENDATION: **Variant A — Lighthouse**
- **Chosen dimensions**: 7H × 6W
- **Why**: Evokes "watching from on high," works in any terminal font, minimal & professional, metaphor is universally understood (beacon = safety & protection).
- **Use case**: CLI startup banner, GitHub README hero, footer watermark.

---

## 2. SVG Specification for GitHub Social Card (16×16 favicon + social preview)

### Monospace-Safe Mark Design
**Name**: "Vigil Eye" icon

**Description**:
A simplified eye-in-beacon motif, bold strokes, monospace-friendly geometry.
- **Core shape**: Vertical rectangle (beacon tower) with a single filled circle (eye) at top, centered.
- **Proportions**: 16px canvas → 4px wide tower, 3px diameter eye, 1px stroke weight (or none; solid fill).
- **Geometry**: Tower is two vertical rectangles (left + right halves), eye is centered circle floating above tower line.
- **Negative space**: Clear gap between eye and tower, so the mark "reads" at favicon size.

**Monospace optimization**: The vertical alignment and minimal curves ensure it renders crisply at 16×16 and upscales to 64×64 (GitHub social card) without anti-aliasing artifacts.

### Color Palette

| Theme | Primary Color | Secondary Color | Recommendation |
|-------|---------------|-----------------|---|
| **Light mode** | `#2c3e50` (dark blue-gray) | `#e74c3c` (alert red) | Primary = tower, Secondary = eye glow |
| **Dark mode** | `#ecf0f1` (light gray) | `#f39c12` (warm amber) | Primary = tower, Secondary = beacon glow |

**Recommended pair for dual-theme logo**: `#2c3e50` (light) + `#ecf0f1` (dark) for tower; eye glow adapts: `#e74c3c` (light theme) / `#f39c12` (dark theme).

**Rationale**: Dark blue-gray reads as "security/professional," amber/red beacon is recognizable (alarms, warnings). Monospace terminals favor high contrast, so light/dark swap keeps clarity across themes.

---

## 3. CLI Splash Banner

### Variant 1 (Recommended)
```
vigil 0.2.0 — watching for AI threats
```
**Length**: 39 chars  
**Tone**: Direct, professional, immediately clear mission.  
**Works for**: Startup logs, systemd status, terminal output.

---

### Variant 2 — Shorter
```
vigil • AI-threat detection
```
**Length**: 28 chars  
**Tone**: Minimalist, bullet point.  
**Works for**: Constrained CLI (smaller terminal widths).

---

### Variant 3 — Formal
```
[vigil] host-based threat detector online
```
**Length**: 41 chars  
**Tone**: Operational/sysadmin language; "[vigil]" prefix like a service tag.  
**Works for**: Structured logs, systemd journals.

---

## RECOMMENDATION: **Variant 1**
```
vigil 0.2.0 — watching for AI threats
```
- **Chosen length**: 39 chars (fits in 80-char terminal nicely)
- **Why**: Directly states mission (AI threats), uses version stamp, "watching" echoes logo metaphor, professional tone without jargon. Easy to log, easy to read.
- **Usage**: Print on daemon startup, include in GitHub Actions CI logs, syslog prefix.

---

## Summary

| Component | Recommendation | Details |
|-----------|---|---|
| **ASCII Logo** | Lighthouse (Variant A) | 7H × 6W; beacon metaphor; CLI-safe |
| **SVG Mark** | Vigil Eye (tower + circle) | 16×16 favicon, monospace-optimized |
| **Color Pair** | `#2c3e50` / `#ecf0f1` | Dark blue-gray + light gray; eye glows in red/amber per theme |
| **CLI Banner** | "vigil 0.2.0 — watching for AI threats" | 39 chars; professional, mission-clear |

---

## Usage Guidelines

1. **ASCII logo**: Paste into README.md `## Logo` section, include in ASCII art docs.
2. **SVG mark**: Export as icon for GitHub social card (1200×630px), favicon, about page.
3. **Color scheme**: Reference in brand guidelines; light theme uses red eye, dark uses amber.
4. **CLI banner**: Hardcode in daemon startup routine; make version dynamic via build flag.
5. **Monospace**: All assets tested in Courier New, Ubuntu Mono, Consolas, Inconsolata.
