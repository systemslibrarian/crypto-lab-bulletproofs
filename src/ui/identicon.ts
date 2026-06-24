/**
 * Deterministic visual fingerprint for a commitment point.
 *
 * A Pedersen commitment is just a 32-byte Ristretto point — abstract and
 * impossible to eyeball. This renders those bytes as a small symmetric SVG so
 * the user can *see* the commitment change the instant the value or blinder
 * changes, reinforcing that it is a deterministic function of (v, γ) that still
 * leaks nothing about v.
 */

const GRID = 5; // 5×5, horizontally mirrored (3 unique columns).

/** Build an SVG identicon string from the compressed point bytes. */
export function identiconSvg(bytes: Uint8Array, size = 80): string {
  if (bytes.length < 6) {
    return `<svg viewBox="0 0 ${size} ${size}" width="${size}" height="${size}" class="identicon" aria-hidden="true"></svg>`;
  }
  const cell = size / GRID;
  const hue = ((bytes[0] << 8) | bytes[1]) % 360;
  const sat = 60 + (bytes[2] % 22); // 60–81%
  const light = 50 + (bytes[3] % 14); // 50–63%
  const fg = `hsl(${hue} ${sat}% ${light}%)`;
  const fg2 = `hsl(${(hue + 42) % 360} ${sat}% ${Math.max(38, light - 10)}%)`;

  let rects = '';
  let n = 0;
  for (let col = 0; col < 3; col++) {
    for (let row = 0; row < GRID; row++) {
      const idx = col * GRID + row; // 0..14
      const byte = bytes[5 + (idx % (bytes.length - 5))];
      const on = ((byte >> (idx % 8)) & 1) === 1;
      if (!on) continue;
      n++;
      const fill = idx % 2 === 0 ? fg : fg2;
      const columns = col === 2 ? [2] : [col, GRID - 1 - col];
      for (const c of columns) {
        rects += `<rect x="${(c * cell).toFixed(2)}" y="${(row * cell).toFixed(2)}" width="${cell.toFixed(2)}" height="${cell.toFixed(2)}" rx="${(cell * 0.2).toFixed(2)}" fill="${fill}"/>`;
      }
    }
  }
  // Guarantee at least one visible cell for all-clear edge cases.
  if (n === 0) {
    rects = `<rect x="${(2 * cell).toFixed(2)}" y="${(2 * cell).toFixed(2)}" width="${cell.toFixed(2)}" height="${cell.toFixed(2)}" rx="${(cell * 0.2).toFixed(2)}" fill="${fg}"/>`;
  }

  return `<svg viewBox="0 0 ${size} ${size}" width="${size}" height="${size}" class="identicon" role="img" aria-label="Visual fingerprint of the commitment point">${rects}</svg>`;
}
