import { getCollection, type CollectionEntry } from 'astro:content';

export type Post = CollectionEntry<'posts'>;

/** All non-draft posts, newest first. */
export async function getPosts(): Promise<Post[]> {
  const posts = await getCollection('posts', ({ data }) => !data.draft);
  return posts.sort(
    (a, b) => b.data.created.valueOf() - a.data.created.valueOf(),
  );
}

export function formatDate(d: Date): string {
  return new Intl.DateTimeFormat('zh-CN', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  }).format(d);
}

export function isoDate(d: Date): string {
  return d.toISOString().slice(0, 10);
}

export function tagSlug(tag: string): string {
  return encodeURIComponent(tag.trim());
}

/** tag -> count, sorted by count desc then name. */
export function tagCounts(posts: Post[]): { tag: string; count: number }[] {
  const map = new Map<string, number>();
  for (const p of posts) {
    for (const t of p.data.tags ?? []) {
      map.set(t, (map.get(t) ?? 0) + 1);
    }
  }
  return [...map.entries()]
    .map(([tag, count]) => ({ tag, count }))
    .sort((a, b) => b.count - a.count || a.tag.localeCompare(b.tag));
}

export function groupByYear(posts: Post[]): [string, Post[]][] {
  const map = new Map<string, Post[]>();
  for (const p of posts) {
    const y = String(p.data.created.getFullYear());
    if (!map.has(y)) map.set(y, []);
    map.get(y)!.push(p);
  }
  return [...map.entries()].sort((a, b) => Number(b[0]) - Number(a[0]));
}
