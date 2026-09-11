import rss from '@astrojs/rss';
import { getPosts } from '../lib/utils';
import { SITE } from '../config';

export async function GET(context) {
  const posts = await getPosts();
  return rss({
    title: SITE.title,
    description: SITE.description,
    site: context.site,
    items: posts.map((post) => ({
      title: post.data.title,
      description: post.data.summary,
      pubDate: post.data.created,
      link: `/posts/${post.id}/`,
      categories: post.data.tags ?? [],
    })),
    customData: `<language>${SITE.lang}</language>`,
  });
}
