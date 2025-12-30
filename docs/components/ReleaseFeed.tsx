'use client';

import { useEffect, useState } from 'react';
import { Tag, Calendar, GitCommit } from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

interface Contributor {
  login: string;
  avatar_url: string;
  html_url: string;
  name?: string;
  commits?: number;
}

interface Release {
  id: number;
  tag_name: string;
  name: string;
  body: string;
  published_at: string;
  html_url: string;
  prerelease: boolean;
  contributors: Contributor[];
}

function ContributorHoverCard({ contributor }: { contributor: Contributor }) {
  return (
    <a
      href={contributor.html_url}
      target="_blank"
      className="group relative inline-block mr-[-6px] hover:mr-1 hover:z-20 transition-all duration-300 ease-spring">
      {/* The Avatar Image */}
      <img
        src={contributor.avatar_url}
        alt={contributor.login}
        className="w-8 h-8 rounded-full border-2 border-fd-card bg-fd-secondary object-cover shadow-sm
                         group-hover:scale-110 group-hover:border-fd-primary/50 transition-all duration-300"
      />

      {/* The Hover Card */}
      <div
        className="absolute bottom-full left-1/2 -translate-x-1/2 mb-3 w-[200px] opacity-0 invisible
                          group-hover:opacity-100 group-hover:visible transition-all duration-200
                          translate-y-2 group-hover:translate-y-0 z-30 pointer-events-none">
        <div className="bg-fd-popover/95 backdrop-blur-md border border-fd-border rounded-xl p-3 shadow-xl flex flex-col items-center gap-2">
          {/* Tiny arrow pointing down */}
          <div className="absolute -bottom-1.5 left-1/2 -translate-x-1/2 w-3 h-3 bg-fd-popover/95 border-b border-r border-fd-border rotate-45" />

          <div className="flex items-center gap-2 w-full">
            <img
              src={contributor.avatar_url}
              className="w-10 h-10 rounded-full border border-fd-border"
              alt={contributor.login}
            />
            <div className="flex flex-col min-w-0">
              <span className="text-sm font-semibold truncate text-fd-foreground">
                {contributor.name || contributor.login}
              </span>
              <span className="text-xs text-fd-muted-foreground truncate">
                @{contributor.login}
              </span>
            </div>
          </div>

          <div className="w-full h-px bg-fd-border/50" />

          <div className="flex items-center justify-between w-full text-xs">
            <div className="flex items-center gap-1.5 text-fd-muted-foreground">
              <GitCommit className="w-3.5 h-3.5" />
              <span>Commits</span>
            </div>
            <span className="font-medium text-fd-primary bg-fd-primary/10 px-2 py-0.5 rounded-full">
              {contributor.commits && contributor.commits > 0
                ? contributor.commits
                : 'Mentioned'}
            </span>
          </div>
        </div>
      </div>
    </a>
  );
}

function ReleaseCard({ release }: { release: Release }) {
  const [expanded, setExpanded] = useState(false);

  // Aggressively clean up release body
  const cleanTag = release.tag_name.replace(/^v/, '');
  const cleanBody = release.body
    .replace(new RegExp(`^#+\\s*\\[?v?${cleanTag}.*`, 'gim'), '')
    .replace(
      new RegExp(
        `^#+\\s*${release.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}.*`,
        'gi',
      ),
      '',
    )
    .replace(/^[\s#*]*\[?v?\d[\d\.\-\w]*\].*$/gm, '')
    .replace(/^\s*#\s*$/gm, '')
    .trim();

  return (
    <div className="flex flex-col gap-2 p-4 bg-fd-card border border-fd-border rounded-xl hover:border-fd-primary/50 transition-colors group/card">
      <div className="flex items-center justify-between flex-wrap gap-y-2">
        <div className="flex items-center gap-3">
          <a
            href={release.html_url}
            target="_blank"
            className="text-lg font-bold text-fd-primary hover:underline flex items-center gap-2">
            <Tag className="w-4 h-4" />
            {release.tag_name}
          </a>
          {release.prerelease && (
            <span className="px-2 py-0.5 text-xs font-medium bg-yellow-500/10 text-yellow-500 rounded-full border border-yellow-500/20">
              Pre-release
            </span>
          )}

          {/* Inline Contributors with Hover Cards */}
          {release.contributors && release.contributors.length > 0 && (
            <div className="flex items-center ml-2 pl-2 border-l border-fd-border h-6">
              <div className="flex items-center">
                {release.contributors.slice(0, 8).map(user => (
                  <ContributorHoverCard key={user.login} contributor={user} />
                ))}
                {release.contributors.length > 8 && (
                  <div className="flex items-center justify-center w-8 h-8 rounded-full bg-fd-secondary border-2 border-fd-card text-[10px] font-medium text-fd-muted-foreground ml-[-6px] relative z-0">
                    +{release.contributors.length - 8}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
        <div className="text-xs text-fd-muted-foreground flex items-center gap-1.5 ml-auto">
          <Calendar className="w-3.5 h-3.5" />
          {new Date(release.published_at).toLocaleDateString()}
        </div>
      </div>

      <div
        className={`prose prose-sm max-w-none text-fd-muted-foreground relative ${!expanded ? 'max-h-[150px] overflow-hidden' : ''}`}
        style={{ marginTop: 0 }}>
        <style jsx global>{`
          .release-body > :first-child {
            margin-top: 0 !important;
          }
        `}</style>
        <div className="release-body pt-2">
          <ReactMarkdown remarkPlugins={[remarkGfm]}>
            {cleanBody || 'No release notes.'}
          </ReactMarkdown>
        </div>

        {!expanded && (
          <div className="absolute bottom-0 left-0 right-0 h-10 bg-gradient-to-t from-fd-card to-transparent" />
        )}
      </div>

      <div className="flex items-center justify-between mt-2">
        <button
          onClick={() => setExpanded(!expanded)}
          className="text-sm font-medium text-fd-foreground hover:text-fd-primary transition-colors">
          {expanded ? 'Show less' : 'Read more'}
        </button>

        <a
          href={release.html_url}
          target="_blank"
          className="text-xs text-fd-muted-foreground hover:text-fd-primary flex items-center gap-1">
          <GitCommit className="w-3.5 h-3.5" />
          GitHub
        </a>
      </div>
    </div>
  );
}

export function ReleaseFeed() {
  const [releases, setReleases] = useState<Release[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(
      'https://api.github.com/repos/margelo/react-native-quick-crypto/releases?per_page=10',
    )
      .then(res => res.json())
      .then(data => {
        if (Array.isArray(data)) {
          setReleases(data.map((r: Release) => ({ ...r, contributors: [] })));
        }
      })
      .catch(err => console.error('Failed to fetch releases:', err))
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="flex flex-col gap-4 my-6">
        {[1, 2, 3].map(i => (
          <div
            key={i}
            className="h-40 bg-fd-secondary/30 rounded-xl animate-pulse"
          />
        ))}
      </div>
    );
  }

  if (releases.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center p-8 border border-dashed border-fd-border rounded-lg bg-fd-card/50">
        <Tag className="w-8 h-8 text-fd-muted-foreground mb-2 opacity-50" />
        <p className="text-sm text-fd-muted-foreground">
          Error getting releases.
        </p>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-4 my-6">
      {releases.map(release => (
        <ReleaseCard key={release.id} release={release} />
      ))}
    </div>
  );
}
