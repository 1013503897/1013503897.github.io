import { visit } from 'unist-util-visit';

/**
 * Convert ```mermaid fenced code blocks into raw <pre class="mermaid"> HTML
 * so Expressive Code / Shiki leaves them alone and the client-side mermaid
 * runtime can render them. Runs at the mdast stage, before highlighting.
 */
export function remarkMermaid() {
  return (tree) => {
    visit(tree, 'code', (node, index, parent) => {
      if (!parent || node.lang !== 'mermaid') return;
      const escaped = String(node.value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
      parent.children[index] = {
        type: 'html',
        value: `<pre class="mermaid not-prose">${escaped}</pre>`,
      };
    });
  };
}
