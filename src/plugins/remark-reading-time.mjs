import getReadingTime from 'reading-time';
import { toString } from 'mdast-util-to-string';

/**
 * Attach reading time + word count to frontmatter (CJK-aware: reading-time
 * counts latin words, so we add a CJK-character estimate at ~350 chars/min).
 */
export function remarkReadingTime() {
  return (tree, file) => {
    const text = toString(tree);
    const latin = getReadingTime(text);
    const cjkCount = (text.match(/[一-鿿]/g) || []).length;
    const minutes = Math.max(1, Math.round(latin.minutes + cjkCount / 350));
    const data = file.data.astro.frontmatter;
    data.minutesRead = `${minutes} 分钟`;
    data.words = Math.round(latin.words + cjkCount);
  };
}
