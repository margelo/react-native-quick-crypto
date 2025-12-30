import NextImage from 'next/image';
import { basePath } from '@/lib/basePath';

interface ImageProps {
  src: string;
  alt: string;
  className?: string;
  width?: number;
  height?: number;
}

export function Image({ src, alt, className, width = 800, height = 400 }: ImageProps) {
  const imageSrc = src.startsWith('/') ? `${basePath}${src}` : src;

  return (
    <NextImage
      src={imageSrc}
      alt={alt}
      width={width}
      height={height}
      className={className}
      style={{ width: '100%', height: 'auto' }}
    />
  );
}
