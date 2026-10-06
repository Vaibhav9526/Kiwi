// Validates that every url(#id) reference in the slide SVG resolves to a
// defined marker, and that no drawable escapes the 1920x1080 viewBox.
const fs = require("fs");

const path = process.argv[2];
const src = fs.readFileSync(path, "utf8");

const ids = new Set([...src.matchAll(/<marker id="([\w-]+)"/g)].map((m) => m[1]));
const refs = [...new Set([...src.matchAll(/url\(#([\w-]+)\)/g)].map((m) => m[1]))];
const missing = refs.filter((r) => !ids.has(r));

console.log(`markers defined : ${[...ids].join(", ")}`);
console.log(`markers referenced: ${refs.join(", ")}`);
console.log(`missing refs     : ${missing.length ? missing.join(", ") : "none"}`);

// Geometry sweep: numeric x/y/width/height on rects must stay in the canvas.
let overflow = [];
for (const m of src.matchAll(/<rect x="(-?[\d.]+)" y="(-?[\d.]+)" width="([\d.]+)" height="([\d.]+)"/g)) {
  const [x, y, w, h] = m.slice(1).map(Number);
  if (x < 0 || y < 0 || x + w > 1920 || y + h > 1080) {
    overflow.push(`rect x=${x} y=${y} w=${w} h=${h}`);
  }
}
console.log(`rects out of frame: ${overflow.length ? overflow.join(" | ") : "none"}`);

// Unresolved chunk markers would mean a half-written slide.
const chunks = (src.match(/<!--CHUNK-->/g) || []).length;
console.log(`leftover CHUNK markers: ${chunks}`);
console.log(`bytes: ${src.length}`);
