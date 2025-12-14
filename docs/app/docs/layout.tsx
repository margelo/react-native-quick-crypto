
import { DocsLayout, type DocsLayoutProps } from 'fumadocs-ui/layouts/docs';
import { baseOptions } from '@/lib/layout.shared';
import { source } from '@/lib/source';
function docsOptions(): DocsLayoutProps {
  return {
    ...baseOptions(),
    tree: source.pageTree,
    links: [],
  };
}
export default function Layout({ children }: { children: React.ReactNode }) {
  return <DocsLayout {...docsOptions()}>{children}</DocsLayout>;
}