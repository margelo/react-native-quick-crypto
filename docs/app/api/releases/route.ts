import { NextResponse } from 'next/server';

export const dynamic = 'force-static';
export const revalidate = false;

function extractContributors(text: string): string[] {
  const mentionRegex = /@([a-zA-Z0-9-]+)/g;
  const matches = text ? text.match(mentionRegex) : null;
  if (!matches) return [];

  const uniqueUsers = Array.from(new Set(matches.map(m => m.substring(1))));
  const banned = ['dependabot', 'github-actions', 'channel', 'here', 'all'];

  return uniqueUsers.filter(
    u => !u.includes('[bot]') && !banned.includes(u.toLowerCase()),
  );
}

interface ContributorDetails {
  login: string;
  name?: string;
  avatar_url: string;
  html_url: string;
  bio?: string;
  location?: string;
  company?: string;
}

async function getContributorDetails(
  login: string,
  headers: Record<string, string>,
): Promise<ContributorDetails | null> {
  try {
    const res = await fetch(`https://api.github.com/users/${login}`, {
      headers,
    });

    if (!res.ok) {
      if (res.status === 404) return null;
      return {
        login,
        avatar_url: `https://github.com/${login}.png`,
        html_url: `https://github.com/${login}`,
      };
    }

    const data = await res.json();
    return {
      login: data.login,
      name: data.name,
      avatar_url: data.avatar_url,
      html_url: data.html_url,
      bio: data.bio,
      location: data.location,
      company: data.company,
    };
  } catch {
    return {
      login,
      avatar_url: `https://github.com/${login}.png`,
      html_url: `https://github.com/${login}`,
    };
  }
}

export async function GET() {
  try {
    const headers: Record<string, string> = process.env.GITHUB_TOKEN
      ? { Authorization: `Bearer ${process.env.GITHUB_TOKEN}` }
      : {};

    const releasesRes = await fetch(
      'https://api.github.com/repos/margelo/react-native-quick-crypto/releases?per_page=10',
      { headers },
    );

    if (!releasesRes.ok) {
      throw new Error(
        `GitHub API Error: ${releasesRes.status} ${releasesRes.statusText}`,
      );
    }

    const releases = await releasesRes.json();
    if (!Array.isArray(releases)) return NextResponse.json([]);

    const enhanced = await Promise.all(
      releases.map(async (release: any, index: number) => {
        const previousTag = releases[index + 1]?.tag_name;
        const contributorsMap = new Map<
          string,
          { login: string; commits: number }
        >();

        extractContributors(release.body).forEach(user => {
          contributorsMap.set(user, { login: user, commits: 0 });
        });

        if (previousTag) {
          try {
            const compareUrl = `https://api.github.com/repos/margelo/react-native-quick-crypto/compare/${previousTag}...${release.tag_name}`;
            const compareRes = await fetch(compareUrl, { headers });

            if (compareRes.ok) {
              const data = await compareRes.json();
              if (data.commits && Array.isArray(data.commits)) {
                data.commits.forEach((commit: any) => {
                  if (commit.author && commit.author.login) {
                    if (!commit.author.login.includes('[bot]')) {
                      const login = commit.author.login;
                      const current = contributorsMap.get(login) || {
                        login,
                        commits: 0,
                      };
                      current.commits++;
                      contributorsMap.set(login, current);
                    }
                  }
                });
              }
            }
          } catch {
            // Ignore compare errors
          }
        }

        const hydratedContributors = await Promise.all(
          Array.from(contributorsMap.values()).map(async c => {
            const details = await getContributorDetails(c.login, headers);
            return {
              ...details,
              commits: c.commits,
            };
          }),
        );

        const sortedContributors = hydratedContributors
          .filter(c => c !== null)
          .sort((a: any, b: any) => b.commits - a.commits);

        return {
          ...release,
          contributors: sortedContributors,
        };
      }),
    );

    return NextResponse.json(enhanced);
  } catch (error) {
    console.error('[API] Handler error:', error);
    return NextResponse.json(
      { error: 'Internal Server Error' },
      { status: 500 },
    );
  }
}
