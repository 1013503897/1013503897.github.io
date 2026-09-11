// @ts-check
import { defineConfig } from 'astro/config';
import sitemap from '@astrojs/sitemap';
import expressiveCode from 'astro-expressive-code';
import pagefind from 'astro-pagefind';

import remarkMath from 'remark-math';
import rehypeKatex from 'rehype-katex';
import rehypeSlug from 'rehype-slug';
import rehypeAutolinkHeadings from 'rehype-autolink-headings';

import { remarkMermaid } from './src/plugins/remark-mermaid.mjs';
import { remarkReadingTime } from './src/plugins/remark-reading-time.mjs';

// Deployed at the user root: https://1013503897.github.io/
export default defineConfig({
  site: 'https://1013503897.github.io',
  base: '/',
  trailingSlash: 'ignore',
  markdown: {
    // Turn ```mermaid fences into <pre class="mermaid"> BEFORE Expressive Code
    // sees them; math + reading time are independent mdast passes.
    remarkPlugins: [remarkMermaid, remarkMath, remarkReadingTime],
    rehypePlugins: [
      rehypeSlug,
      [rehypeAutolinkHeadings, { behavior: 'wrap', properties: { className: ['heading-anchor'] } }],
      rehypeKatex,
    ],
  },
  integrations: [
    // Expressive Code must be registered before anything that finalizes markdown.
    expressiveCode({
      themes: ['github-dark', 'github-light'],
      themeCssSelector: (theme) => `[data-theme="${theme.type}"]`,
      styleOverrides: {
        borderRadius: '0.6rem',
        codeFontFamily:
          "'JetBrains Mono', ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, monospace",
        codeFontSize: '0.85rem',
        frames: { shadowColor: 'transparent' },
      },
      defaultProps: { wrap: false, showLineNumbers: false },
      // reverse-engineering dumps use langs Shiki doesn't bundle; alias the
      // close ones and let the rest fall back to plain text quietly.
      shiki: { langAlias: { aidl: 'java', smali: 'asm' } },
    }),
    sitemap(),
    pagefind(),
  ],
});
