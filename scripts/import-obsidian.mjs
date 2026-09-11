#!/usr/bin/env node
/**
 * Import Obsidian notes marked `publish: true` from the vault's 发表文章 area
 * into this Astro project's content collection.
 *
 *   vault/发表文章/<folder>/<file>.md          (publish: true, slug: xxx)
 *        └─ images/ figures/ evidence/ ...
 *
 *   → src/content/posts/<slug>/index.md
 *        └─ assets/<flattened-image-names>
 *
 * Transforms applied to each note:
 *   - whitelist + normalise frontmatter (title/summary/created/updated/tags/venue/target)
 *   - resolve every ![](path) / ![[embed]] image relative to the note, copy it
 *     into assets/, and rewrite the link to ./assets/<name>
 *   - flatten Obsidian wikilinks [[target|alias]] / [[target]] to plain text
 *     (cross-note links point at unpublished case notes, so we don't link them)
 *
 * Idempotent: wipes and regenerates src/content/posts on every run.
 */
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import matter from 'gray-matter';

const VAULT = process.env.VAULT_DIR
  || path.join(os.homedir(), 'Documents/obsidian-vault');
const SRC_DIR = path.join(VAULT, '发表文章');
const OUT_DIR = path.join(process.cwd(), 'src/content/posts');

const IMG_EXT = new Set(['.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.avif']);

/** recursively collect .md files */
function walk(dir, acc = []) {
  for (const name of fs.readdirSync(dir)) {
    const fp = path.join(dir, name);
    const st = fs.statSync(fp);
    if (st.isDirectory()) {
      if (name === '_archive' || name.startsWith('.')) continue;
      walk(fp, acc);
    } else if (name.endsWith('.md')) {
      acc.push(fp);
    }
  }
  return acc;
}

/** locate an embedded/relative asset given the note dir and a reference */
function resolveAsset(noteDir, ref) {
  // strip anchors/queries and Obsidian size suffix (|300)
  const clean = ref.split('#')[0].split('|')[0].trim();
  // 1) direct relative resolve
  const direct = path.resolve(noteDir, clean);
  if (fs.existsSync(direct) && fs.statSync(direct).isFile()) return direct;
  // 2) basename search under the note's folder tree (Obsidian shortest-path)
  const base = path.basename(clean);
  const found = findByName(noteDir, base);
  if (found) return found;
  return null;
}

const nameCache = new Map();
function findByName(root, name) {
  const key = root;
  let index = nameCache.get(key);
  if (!index) {
    index = new Map();
    const stack = [root];
    while (stack.length) {
      const d = stack.pop();
      let entries = [];
      try { entries = fs.readdirSync(d); } catch { continue; }
      for (const e of entries) {
        const fp = path.join(d, e);
        let st;
        try { st = fs.statSync(fp); } catch { continue; }
        if (st.isDirectory()) { if (e !== '_archive') stack.push(fp); }
        else if (!index.has(e)) index.set(e, fp);
      }
    }
    nameCache.set(key, index);
  }
  return index.get(name) || null;
}

function slugifyAsset(rel) {
  return rel
    .replace(/^\.\.\//g, '')
    .replace(/[\\/]/g, '-')
    .replace(/\s+/g, '_');
}

function processBody(body, noteDir, assetsDir) {
  const copied = new Map(); // absPath -> ./assets/name
  let assetCount = 0;

  const ensureAsset = (absPath) => {
    if (copied.has(absPath)) return copied.get(absPath);
    const relFromNote = path.relative(noteDir, absPath);
    let outName = slugifyAsset(relFromNote);
    // guard against collisions after flattening
    let dest = path.join(assetsDir, outName);
    let i = 1;
    while (fs.existsSync(dest) && fs.readFileSync(dest).length !== fs.statSync(absPath).size) {
      const ext = path.extname(outName);
      outName = outName.slice(0, -ext.length) + '_' + i + ext;
      dest = path.join(assetsDir, outName);
      i++;
    }
    fs.mkdirSync(assetsDir, { recursive: true });
    fs.copyFileSync(absPath, dest);
    assetCount++;
    const webPath = './assets/' + outName;
    copied.set(absPath, webPath);
    return webPath;
  };

  let out = body;

  // 0) Drop a single leading H1 — the layout already renders the title as <h1>,
  // so the article's own "# ..." would duplicate it.
  out = out.replace(/^﻿?\s*#[ \t]+.*(?:\r?\n)+/, '');

  // 1) Obsidian embeds ![[path]] (images only; drop note transclusions)
  out = out.replace(/!\[\[([^\]]+)\]\]/g, (m, inner) => {
    const ref = inner.split('|')[0].trim();
    const ext = path.extname(ref).toLowerCase();
    if (!IMG_EXT.has(ext)) return ''; // note transclusion -> drop
    const abs = resolveAsset(noteDir, ref);
    if (!abs) { console.warn('  ! missing embed:', ref); return ''; }
    const alt = inner.includes('|') ? inner.split('|').slice(1).join('|') : path.basename(ref, ext);
    return `![${alt}](${ensureAsset(abs)})`;
  });

  // 2) Standard image links ![alt](path) with a local (non-http) target.
  // Alt text may itself contain "]" (e.g. byte[] or S[i]) — accept any "]"
  // that is not immediately followed by "(".
  out = out.replace(/!\[((?:[^\]]|\](?!\())*)\]\(([^)]+)\)/g, (m, alt, url) => {
    const u = url.trim();
    if (/^https?:\/\//i.test(u) || u.startsWith('data:') || u.startsWith('/')) return m;
    const abs = resolveAsset(noteDir, decodeURIComponent(u));
    if (!abs) {
      console.warn('  ! missing image:', u);
      // avoid a broken/​build-breaking relative link
      return `*（图待补：${alt || path.basename(u)}）*`;
    }
    return `![${alt}](${ensureAsset(abs)})`;
  });

  // 3) Wikilinks [[target|alias]] / [[target]] -> plain text (no dead links)
  out = out.replace(/(?<!!)\[\[([^\]]+)\]\]/g, (m, inner) => {
    const parts = inner.split('|');
    const text = (parts.length > 1 ? parts.slice(1).join('|') : parts[0]).trim();
    // use last path segment for bare targets
    return text.includes('/') ? text.split('/').pop() : text;
  });

  return { body: out, assetCount };
}

function normDate(v) {
  if (!v) return undefined;
  if (v instanceof Date) return v.toISOString().slice(0, 10);
  return String(v).slice(0, 10);
}

function run() {
  if (!fs.existsSync(SRC_DIR)) {
    console.error('vault source not found:', SRC_DIR);
    process.exit(1);
  }
  // clean output
  fs.rmSync(OUT_DIR, { recursive: true, force: true });
  fs.mkdirSync(OUT_DIR, { recursive: true });

  const md = walk(SRC_DIR);
  const seen = new Set();
  let n = 0;

  for (const fp of md) {
    const raw = fs.readFileSync(fp, 'utf8');
    let parsed;
    try { parsed = matter(raw); } catch (e) { console.warn('skip (bad frontmatter):', fp); continue; }
    const fm = parsed.data || {};
    if (fm.publish !== true) continue;

    const slug = (fm.slug || path.basename(path.dirname(fp))).toString().trim();
    if (seen.has(slug)) { console.error('DUPLICATE slug:', slug, fp); continue; }
    seen.add(slug);

    const noteDir = path.dirname(fp);
    const outDir = path.join(OUT_DIR, slug);
    const assetsDir = path.join(outDir, 'assets');
    fs.mkdirSync(outDir, { recursive: true });

    console.log(`→ ${slug}  (${path.relative(VAULT, fp)})`);
    const { body, assetCount } = processBody(parsed.content, noteDir, assetsDir);

    const front = {
      title: fm.title || slug,
      summary: fm.summary || '',
      created: normDate(fm.created) || normDate(fm.date) || '1970-01-01',
      ...(fm.updated ? { updated: normDate(fm.updated) } : {}),
      // handle both proper YAML arrays and the odd note that used fullwidth
      // commas inside [ ... ] (which YAML reads as a single string element)
      tags: (Array.isArray(fm.tags) ? fm.tags : fm.tags ? [fm.tags] : [])
        .flatMap((t) => String(t).split(/[，,]/))
        .map((t) => t.trim())
        .filter(Boolean),
      ...(fm.venue ? { venue: String(fm.venue) } : {}),
      ...(fm.target ? { target: String(fm.target) } : {}),
      source: path.relative(VAULT, fp),
    };

    const outMd = matter.stringify('\n' + body.replace(/^\n+/, ''), front);
    fs.writeFileSync(path.join(outDir, 'index.md'), outMd);
    console.log(`   ${assetCount} asset(s)`);
    n++;
  }

  console.log(`\n✔ imported ${n} post(s) → ${path.relative(process.cwd(), OUT_DIR)}`);
  if (n === 0) process.exit(2);
}

run();
