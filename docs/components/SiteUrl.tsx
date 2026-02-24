'use client';

import { basePath } from '@/lib/basePath';
import { useEffect, useState } from 'react';

export function SiteUrl({ path }: { path: string }) {
  const [origin, setOrigin] = useState('https://margelo.github.io');

  useEffect(() => {
    setOrigin(window.location.origin);
  }, []);

  const url = `${origin}${basePath}${path}`;

  return <code>{url}</code>;
}
