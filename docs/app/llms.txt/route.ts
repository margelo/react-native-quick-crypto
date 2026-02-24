import { basePath } from '@/lib/basePath';
import { getLLMSummary, source } from '@/lib/source';

export const revalidate = false;

const origin = 'https://margelo.github.io';

export async function GET() {
  const pages = source.getPages().map(getLLMSummary);

  const lines = [
    '# React Native Quick Crypto',
    '',
    '> Drop-in replacement for Node.js crypto on React Native, powered by OpenSSL 3.6+ and Nitro Modules.',
    '',
    'Documentation for the react-native-quick-crypto library.',
    '',
    '## Docs',
    '',
    ...pages.map(
      p => `- [${p.title}](${origin}${basePath}${p.url}): ${p.description}`,
    ),
  ];

  return new Response(lines.join('\n'), {
    headers: { 'Content-Type': 'text/plain; charset=utf-8' },
  });
}
