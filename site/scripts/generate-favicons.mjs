import sharp from "sharp";
import { fileURLToPath } from "node:url";
import path from "node:path";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, "..");
const source = path.join(root, "public/brand/aegis-icon-app.svg");

const targets = [
  { size: 32, out: "public/favicon-32.png" },
  { size: 180, out: "public/apple-touch-icon.png" },
  { size: 512, out: "public/icon-512.png" },
];

for (const { size, out } of targets) {
  const dest = path.join(root, out);
  await sharp(source, { density: 384 })
    .resize(size, size)
    .png()
    .toFile(dest);
  console.log(`wrote ${out} (${size}x${size})`);
}
