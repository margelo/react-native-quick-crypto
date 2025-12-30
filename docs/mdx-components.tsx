import defaultMdxComponents from 'fumadocs-ui/mdx';
import type { MDXComponents } from 'mdx/types';
import { Mermaid } from '@/components/mdx/mermaid';
import * as Twoslash from 'fumadocs-twoslash/ui';
import NextImage from 'next/image';
import { basePath } from '@/lib/basePath';

function MdxImage(
  props: React.ComponentProps<'img'> & { src?: string | { src: string } },
) {
  const { src, alt, className } = props;

  // Handle both string src and object src (fumadocs may pass either)
  const srcString = typeof src === 'string' ? src : src?.src;
  if (!srcString) return null;

  // Only add basePath if not already present and path is absolute
  const needsBasePath =
    basePath && srcString.startsWith('/') && !srcString.startsWith(basePath);
  const imageSrc = needsBasePath ? `${basePath}${srcString}` : srcString;

  return (
    <NextImage
      src={imageSrc}
      alt={alt ?? ''}
      width={800}
      height={400}
      className={className}
      style={{ width: '100%', height: 'auto' }}
    />
  );
}

export function getMDXComponents(components?: MDXComponents): MDXComponents {
  return {
    ...defaultMdxComponents,
    Mermaid,
    ...Twoslash,
    img: MdxImage,
    ...components,
  };
}
