import { docs } from 'fumadocs-mdx:collections/server';
import { type InferPageType, loader } from 'fumadocs-core/source';
import { lucideIconsPlugin } from 'fumadocs-core/source/lucide-icons';

// See https://fumadocs.dev/docs/headless/source-api for more info
export const source = loader({
  baseUrl: '/docs',
  source: docs.toFumadocsSource(),
  plugins: [lucideIconsPlugin()],
});

export function getPageImage(page: InferPageType<typeof source>) {
  const segments = [...page.slugs, 'image.png'];

  return {
    segments,
    url: `/og/docs/${segments.join('/')}`,
  };
}

function stripMdx(text: string): string {
  return (
    text
      // Remove import statements
      .replace(/^import\s+.*?(?:from\s+)?['"].*?['"];?\s*$/gm, '')
      // Remove export statements (non-default)
      .replace(/^export\s+(?!default).*$/gm, '')
      // Remove self-closing JSX components (e.g. <TypeTable ... />, <Mermaid ... />)
      .replace(
        /<(?:TypeTable|Mermaid|Cards|Card|Steps|Step|Tab|Tabs)\b[^]*?\/>/gs,
        '',
      )
      // Remove opening+closing JSX components with children
      .replace(
        /<(Callout|Cards|Card|Steps|Step|Tab|Tabs)\b[^>]*>([\s\S]*?)<\/\1>/g,
        (_match, _tag, children: string) => children.trim(),
      )
      // Remove remaining self-closing JSX tags
      .replace(/<[A-Z]\w+\b[^]*?\/>/gs, '')
      // Remove remaining opening JSX tags (orphaned)
      .replace(/<[A-Z]\w+\b[^>]*>/g, '')
      // Remove remaining closing JSX tags (orphaned)
      .replace(/<\/[A-Z]\w+>/g, '')
      // Collapse 3+ newlines into 2
      .replace(/\n{3,}/g, '\n\n')
      .trim()
  );
}

export async function getLLMText(page: InferPageType<typeof source>) {
  const processed = await page.data.getText('processed');

  return `# ${page.data.title} (${page.url})

${stripMdx(processed)}`;
}

export function getLLMSummary(page: InferPageType<typeof source>) {
  return {
    title: page.data.title,
    description: page.data.description ?? '',
    url: page.url,
  };
}
