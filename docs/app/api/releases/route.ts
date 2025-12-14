import { NextResponse } from 'next/server';
import { unstable_cache } from 'next/cache';

export const revalidate = 86400; // Cache response for 24 hours (releases don't change often)

function extractContributors(text: string): string[] {
    const mentionRegex = /@([a-zA-Z0-9-]+)/g;
    const matches = text ? text.match(mentionRegex) : null;
    if (!matches) return [];

    // Clean up matches, remove duplicates, and filter out common bots/keywords
    const uniqueUsers = Array.from(new Set(matches.map(m => m.substring(1)))); // remove @
    const banned = ['dependabot', 'github-actions', 'channel', 'here', 'all']; // common non-user mentions

    return uniqueUsers.filter(u => !u.includes('[bot]') && !banned.includes(u.toLowerCase()));
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

// Persistently cache user details forever (or until manually invalidated)
// This fetches the "real name" and other details from GitHub User API
const getContributorDetails = unstable_cache(
    async (login: string): Promise<ContributorDetails | null> => {
        try {
            console.log(`[API] Fetching user details for ${login}...`);
            const headers: Record<string, string> = process.env.GITHUB_TOKEN ? { Authorization: `Bearer ${process.env.GITHUB_TOKEN}` } : {};
            const res = await fetch(`https://api.github.com/users/${login}`, { headers });

            if (!res.ok) {
                if (res.status === 404) return null;
                throw new Error(`GitHub User API Error: ${res.status}`);
            }

            const data = await res.json();
            return {
                login: data.login,
                name: data.name,
                avatar_url: data.avatar_url,
                html_url: data.html_url,
                bio: data.bio,
                location: data.location,
                company: data.company
            };
        } catch (e) {
            console.error(`[API] Failed to fetch user ${login}:`, e);
            // Fallback to basic details if API fails
            return {
                login,
                avatar_url: `https://github.com/${login}.png`,
                html_url: `https://github.com/${login}`
            };
        }
    },
    ['github-user-details'], // Cache key namespace
    {
        revalidate: false, // Cache forever (never revalidate automatically)
        tags: ['contributors']
    }
);

export async function GET() {
    try {
        console.log('[API] Fetching releases from GitHub...');
        const headers: Record<string, string> = process.env.GITHUB_TOKEN ? { Authorization: `Bearer ${process.env.GITHUB_TOKEN}` } : {};

        const releasesRes = await fetch('https://api.github.com/repos/margelo/react-native-quick-crypto/releases?per_page=10', {
            headers,
            next: { revalidate: 86400 }
        });

        if (!releasesRes.ok) {
            console.error('[API] GitHub Releases fetch failed:', releasesRes.status, releasesRes.statusText);
            throw new Error(`GitHub API Error: ${releasesRes.status} ${releasesRes.statusText}`);
        }

        const releases = await releasesRes.json();
        if (!Array.isArray(releases)) return NextResponse.json([]);

        // Process releases in parallel to fetch contributors
        const enhanced = await Promise.all(releases.map(async (release: any, index: number) => {
            const previousTag = releases[index + 1]?.tag_name;
            const contributorsMap = new Map<string, { login: string, commits: number }>();

            // 1. Text mentions (legacy method, but good for shoutouts)
            extractContributors(release.body).forEach(user => {
                contributorsMap.set(user, { login: user, commits: 0 });
            });

            // 2. Compare API (if previous tag exists) to get actual committers
            if (previousTag) {
                try {
                    const compareUrl = `https://api.github.com/repos/margelo/react-native-quick-crypto/compare/${previousTag}...${release.tag_name}`;
                    const compareRes = await fetch(compareUrl, { headers, next: { revalidate: 86400 } });

                    if (compareRes.ok) {
                        const data = await compareRes.json();
                        if (data.commits && Array.isArray(data.commits)) {
                            data.commits.forEach((commit: any) => {
                                if (commit.author && commit.author.login) {
                                    if (!commit.author.login.includes('[bot]')) {
                                        const login = commit.author.login;
                                        const current = contributorsMap.get(login) || { login, commits: 0 };
                                        current.commits++;
                                        contributorsMap.set(login, current);
                                    }
                                }
                            });
                        }
                    } else if (compareRes.status === 403 && process.env.NODE_ENV === 'development') {
                        // Mock data for development when rate limited
                        console.warn(`[API] Rate limited. Using mock contributors for ${release.tag_name}.`);
                        ['mrousavy', 'szymonkapala', 'ospfranco'].forEach(login => {
                            contributorsMap.set(login, { login, commits: Math.floor(Math.random() * 5) + 1 });
                        });
                    } else {
                        console.warn(`[API] Compare fetch failed for ${previousTag}...${release.tag_name}: ${compareRes.status}`);
                    }
                } catch (e) {
                    console.error('[API] Compare fetch error:', e);
                }
            }

            // 3. Hydrate with full user details (Names, Bios, etc.) using persistent cache
            const hydratedContributors = await Promise.all(
                Array.from(contributorsMap.values()).map(async (c) => {
                    const details = await getContributorDetails(c.login);
                    return {
                        ...details,
                        commits: c.commits
                    };
                })
            );

            // Sort: High commits first, then by name
            const sortedContributors = hydratedContributors
                .filter(c => c !== null)
                .sort((a: any, b: any) => b.commits - a.commits);

            return {
                ...release,
                contributors: sortedContributors
            };
        }));

        return NextResponse.json(enhanced);
    } catch (error) {
        console.error('[API] Handler error:', error);
        return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
    }
}
