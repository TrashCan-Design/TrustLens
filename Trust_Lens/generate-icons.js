/**
 * generate-icons.js
 * Generates PNG icons for TrustLens at 16, 32, 48, 128px
 * Run with: node generate-icons.js
 * Requires: npm install canvas (only for icon generation, not part of the extension)
 */

const { createCanvas } = require('canvas');
const fs = require('fs');
const path = require('path');

const SIZES = [16, 32, 48, 128];
const OUT_DIR = path.join(__dirname, 'icons');

if (!fs.existsSync(OUT_DIR)) fs.mkdirSync(OUT_DIR);

function drawIcon(size) {
  const canvas = createCanvas(size, size);
  const ctx = canvas.getContext('2d');

  const cx = size / 2;
  const cy = size / 2;
  const r = size * 0.42;
  const strokeW = Math.max(1.5, size * 0.06);

  // Background
  ctx.fillStyle = '#0f1117';
  ctx.beginPath();
  ctx.roundRect(0, 0, size, size, size * 0.18);
  ctx.fill();

  // Shield path (simplified polygon)
  const s = size * 0.82;
  const sx = (size - s) / 2;
  const sy = (size - s) / 2;

  ctx.beginPath();
  ctx.moveTo(cx, sy + s * 0.05);
  ctx.lineTo(sx + s * 0.88, sy + s * 0.22);
  ctx.lineTo(sx + s * 0.88, sy + s * 0.55);
  ctx.quadraticCurveTo(sx + s * 0.88, sy + s * 0.88, cx, sy + s * 0.95);
  ctx.quadraticCurveTo(sx + s * 0.12, sy + s * 0.88, sx + s * 0.12, sy + s * 0.55);
  ctx.lineTo(sx + s * 0.12, sy + s * 0.22);
  ctx.closePath();

  // Fill shield with slight glow
  ctx.fillStyle = 'rgba(0, 229, 255, 0.10)';
  ctx.fill();

  // Stroke
  ctx.strokeStyle = '#00e5ff';
  ctx.lineWidth = strokeW;
  ctx.lineJoin = 'round';
  ctx.stroke();

  // Inner checkmark / lens dot at larger sizes
  if (size >= 32) {
    const dotR = size * 0.12;
    const grd = ctx.createRadialGradient(cx, cy + size * 0.04, 0, cx, cy + size * 0.04, dotR * 1.5);
    grd.addColorStop(0, 'rgba(0,229,255,0.9)');
    grd.addColorStop(1, 'rgba(0,229,255,0)');
    ctx.beginPath();
    ctx.arc(cx, cy + size * 0.04, dotR, 0, Math.PI * 2);
    ctx.fillStyle = grd;
    ctx.fill();
  }

  return canvas.toBuffer('image/png');
}

SIZES.forEach(size => {
  const buf = drawIcon(size);
  const outPath = path.join(OUT_DIR, `icon${size}.png`);
  fs.writeFileSync(outPath, buf);
  console.log(`Generated ${outPath}`);
});

console.log('All icons generated.');
