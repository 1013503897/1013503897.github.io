# 星野安全 · 逆向手记

移动安全 / 逆向工程技术博客，基于 [Astro](https://astro.build) 构建，内容从 Obsidian
作品集库（`发表文章/`）导入。部署到 GitHub Pages：<https://1013503897.github.io/>

## 技术栈

- **Astro 6** — 静态站点，零运行时 JS（除搜索 / 图表）
- **Expressive Code**（Shiki）— 代码高亮、复制按钮、明暗双主题
- **Tailwind v4**（`@tailwindcss/postcss`）+ Typography — 排版
- **KaTeX** — 数学公式（`$…$` / `$$…$$`）
- **Mermaid**（客户端）— ` ```mermaid ` 代码块渲染为图表，随主题切换
- **Pagefind** — 构建期生成的全文搜索索引
- RSS（`/rss.xml`）、sitemap、标签页、深色模式

## 内容从哪来

文章源在 Obsidian 库 `~/Documents/obsidian-vault/发表文章/`。**只有 frontmatter 标了
`publish: true` 的笔记会上站**。每篇需要：

```yaml
---
title: 文章标题
publish: true
slug: url-slug            # 决定 /posts/<slug>/
summary: 首页与卡片上的一句话摘要
created: 2026-07-26
tags: [移动安全, 逆向, ...]
venue: 看雪                # 可选，显示为徽章
target: 分析目标            # 可选，原样显示（不解码作者的 base64 脱敏）
---
```

`scripts/import-obsidian.mjs` 把这些笔记拷进 `src/content/posts/<slug>/`，并：

- 把 `images/…`、`../images/…`、Obsidian `![[embed]]` 图片就地拷到 `assets/` 并改写链接
- 把 wikilink `[[目标|别名]]` 压成纯文本（跨笔记链接指向未发布的案例笔记，故不生成死链）
- 去掉与标题重复的首个 `# H1`
- ` ```mermaid ` 交给客户端渲染；数学、代码走 remark/rehype

> 导入是**单向拷贝**：`src/content/posts/` 每次 `import` 会清空重建，别手改里面的文件，
> 改源笔记再重新导入。库路径可用 `VAULT_DIR` 环境变量覆盖。

## 本地开发

```bash
npm install
npm run import     # 从 Obsidian 库导入已发布文章
npm run dev        # http://localhost:4321
npm run sync       # import + build（含 Pagefind 索引）
```

## 发布

推送到 `master` 即触发 `.github/workflows/deploy.yml`（Astro build → Pagefind →
GitHub Pages）。**注意**：CI 只构建仓库里已提交的 `src/content/posts/`，不读 Obsidian
库——写完新文章要先在本地 `npm run import` 并提交生成的 Markdown，再推送。

## 加一篇新文章

1. 在库里给目标笔记加 `publish: true` + `slug` + `summary`
2. `npm run import && npm run dev` 本地预览
3. `git add src/content/posts && git commit && git push`
