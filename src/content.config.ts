import { defineCollection, z } from 'astro:content';
import { glob } from 'astro/loaders';

const posts = defineCollection({
  // Each imported article lives at src/content/posts/<slug>/index.md
  loader: glob({ pattern: '**/index.md', base: './src/content/posts' }),
  schema: z.object({
    title: z.string(),
    summary: z.string().optional().default(''),
    // dates come in as YYYY-MM-DD strings from Obsidian frontmatter
    created: z.coerce.date(),
    updated: z.coerce.date().optional(),
    tags: z.array(z.string()).optional().default([]),
    venue: z.string().optional(),
    target: z.string().optional(),
    draft: z.boolean().optional().default(false),
    // original vault-relative source path, for reference only
    source: z.string().optional(),
  }),
});

export const collections = { posts };
