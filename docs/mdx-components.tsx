import defaultMdxComponents from 'fumadocs-ui/mdx';
import type { MDXComponents } from 'mdx/types';
import { Mermaid } from '@/components/mdx/mermaid';
import * as Twoslash from 'fumadocs-twoslash/ui';
import NextImage from 'next/image';

function MdxImage(props: React.ComponentProps<'img'>) {
  const { src, alt, className } = props;
  if (!src || typeof src !== 'string') return null;

  return (
    <NextImage
      src={src}
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
