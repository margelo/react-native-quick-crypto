'use client';

import { useEffect, useState } from 'react';

interface Contributor {
  login: string;
  avatar_url: string;
  html_url: string;
  contributions: number;
}

export function ContributorGrid() {
  const [contributors, setContributors] = useState<Contributor[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(
      'https://api.github.com/repos/margelo/react-native-quick-crypto/contributors?per_page=100',
    )
      .then(res => res.json())
      .then(data => {
        if (Array.isArray(data)) {
          const humans = data.filter(
            (c: Contributor) => !c.login.toLowerCase().includes('[bot]'),
          );
          setContributors(humans);
        }
      })
      .catch(err => console.error('Failed to fetch contributors:', err))
      .finally(() => setLoading(false));
  }, []);

  // Sort by contributions (descending)
  const sortedContributors = contributors.sort(
    (a, b) => b.contributions - a.contributions,
  );

  if (loading) {
    return (
      <div className="text-sm text-fd-muted-foreground animate-pulse my-6">
        Loading contributors...
      </div>
    );
  }

  if (contributors.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center p-8 border border-dashed border-fd-border rounded-lg bg-fd-card/50">
        <p className="text-sm text-fd-muted-foreground">
          No contributors found.
        </p>
      </div>
    );
  }

  return (
    <div className="grid grid-cols-3 sm:grid-cols-4 md:grid-cols-5 lg:grid-cols-6 gap-3">
      {sortedContributors.map(c => (
        <a
          key={c.login}
          href={c.html_url}
          target="_blank"
          className="flex flex-col items-center bg-fd-card border border-fd-border rounded-lg hover:border-fd-primary/50 hover:bg-fd-secondary/30 transition-all no-underline group overflow-hidden p-0">
          <img
            src={c.avatar_url}
            alt={c.login}
            className="w-full aspect-square object-cover transition-transform group-hover:scale-105 !m-0 block"
          />
          <div className="w-full p-2 text-center border-t border-fd-border/50 bg-fd-card/50">
            <span className="text-xs font-medium text-fd-foreground truncate block group-hover:text-fd-primary transition-colors">
              {c.login}
            </span>
          </div>
        </a>
      ))}
    </div>
  );
}
