import { NextResponse } from 'next/server';

export const dynamic = 'force-static';
export const revalidate = false;

export async function GET() {
  try {
    console.log('[API] Fetching contributors from GitHub...');
    const headers: Record<string, string> = process.env.GITHUB_TOKEN
      ? { Authorization: `Bearer ${process.env.GITHUB_TOKEN}` }
      : {};

    const res = await fetch(
      'https://api.github.com/repos/margelo/react-native-quick-crypto/contributors?per_page=100',
      {
        headers,
        next: { revalidate: 86400 },
      },
    );

    if (!res.ok) {
      console.error(
        '[API] GitHub Contributors fetch failed:',
        res.status,
        res.statusText,
      );
      throw new Error(`GitHub API Error: ${res.status} ${res.statusText}`);
    }

    const data = await res.json();

    if (!Array.isArray(data)) return NextResponse.json([]);

    const humans = data.filter(
      (c: any) => !c.login.toLowerCase().includes('[bot]'),
    );

    return NextResponse.json(humans);
  } catch (error) {
    console.error('[API] Handler error:', error);
    return NextResponse.json(
      { error: 'Internal Server Error' },
      { status: 500 },
    );
  }
}
