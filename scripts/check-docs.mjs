import { readdirSync, readFileSync, existsSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const excluded = new Set(['.git', '.cache', 'node_modules', 'dist']);
function markdownFiles(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) return excluded.has(entry.name) ? [] : markdownFiles(full);
    return entry.name.endsWith('.md') ? [full] : [];
  });
}

const errors = [];
const documents = new Map();
for (const file of markdownFiles(root)) {
  const lines = readFileSync(file, 'utf8').split(/\r?\n/);
  let fence;
  const text = [];
  for (const [index, line] of lines.entries()) {
    const marker = line.match(/^\s{0,3}(`{3,}|~{3,})(.*)$/);
    if (marker && !fence) { fence = marker[1]; continue; }
    if (marker && marker[1][0] === fence?.[0] && marker[1].length >= fence.length && !marker[2].trim()) {
      fence = undefined;
      continue;
    }
    if (!fence) text.push({ line, number: index + 1 });
  }
  if (fence) errors.push(`${path.relative(root, file)}: bloque de código sin cerrar`);
  const anchors = new Set();
  const repeats = new Map();
  for (const { line } of text) {
    const heading = line.match(/^ {0,3}#{1,6}\s+(.+?)\s*#*$/);
    if (heading) {
      const slug = heading[1].toLowerCase().replace(/<[^>]*>/g, '').replace(/[^\p{L}\p{N}\p{M}_\s-]/gu, '').replace(/ /g, '-');
      const count = repeats.get(slug) || 0;
      anchors.add(count ? `${slug}-${count}` : slug);
      repeats.set(slug, count + 1);
    }
    for (const match of line.matchAll(/\b(?:id|name)=["']([^"']+)["']/g)) anchors.add(match[1]);
  }
  documents.set(file, { text, anchors });
}

let links = 0;
for (const [file, { text }] of documents) {
  for (const { line, number } of text) {
    for (const match of line.matchAll(/!?\[[^\]]*\]\((<[^>]+>|[^\s)]+)(?:\s+"[^"]*")?\)/g)) {
      const href = match[1].replace(/^<|>$/g, '');
      if (/^[a-z][a-z\d+.-]*:/i.test(href) || href.startsWith('//')) continue;
      links++;
      const [relative, fragment] = href.split('#');
      const target = relative ? path.resolve(path.dirname(file), decodeURIComponent(relative)) : file;
      const label = `${path.relative(root, file)}:${number}: ${href}`;
      if (!existsSync(target)) errors.push(`${label}: destino ausente`);
      else if (fragment && statSync(target).isFile() && target.endsWith('.md') && !documents.get(target)?.anchors.has(decodeURIComponent(fragment))) {
        errors.push(`${label}: ancla ausente`);
      }
    }
  }
}
for (const feature of ['FEAT-001-authentication', 'FEAT-002-user-management', 'FEAT-003-dashboard']) {
  for (const name of ['spec.md', 'plan.md', 'tasks.md']) {
    const file = path.join(root, 'docs', 'features', feature, name);
    if (!existsSync(file)) errors.push(`Paquete incompleto: ${file}`);
  }
}
if (errors.length) {
  console.error(errors.join('\n'));
  process.exit(1);
}
console.log(`${documents.size} Markdown: ${links} enlaces/anclas locales, bloques de código y estructura de features válidos.`);
