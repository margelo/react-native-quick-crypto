'use client';

import { useState } from 'react';
import {
  COVERAGE_DATA,
  CoverageItem,
  CapabilityStatus,
} from '../data/coverage';
import {
  CheckCircle2,
  XCircle,
  AlertTriangle,
  MinusCircle,
  SearchX,
} from 'lucide-react';

export function CoverageTable() {
  const [search, setSearch] = useState('');

  const deriveStatus = (item: CoverageItem): CapabilityStatus => {
    if (!item.subItems || item.subItems.length === 0) {
      return item.status || 'missing';
    }

    const subStatuses = item.subItems.map(deriveStatus);
    const applicable = subStatuses.filter(s => s !== 'not-in-node');

    if (applicable.length === 0) return 'not-in-node';

    const allImplemented = applicable.every(s => s === 'implemented');
    const allMissing = applicable.every(s => s === 'missing');

    if (allImplemented) return 'implemented';
    if (allMissing) return 'missing';

    return 'partial';
  };

  const filterItems = (items: CoverageItem[]): CoverageItem[] => {
    return items
      .map(item => {
        const matches = item.name.toLowerCase().includes(search.toLowerCase());
        const subMatches = item.subItems ? filterItems(item.subItems) : [];

        if (matches || subMatches.length > 0) {
          const newItem = { ...item, subItems: subMatches };
          // If we have sub-items (either filtered or original if matches), recalculate status
          if (newItem.subItems && newItem.subItems.length > 0) {
            newItem.status = deriveStatus(newItem);
          } else if (item.subItems && item.subItems.length > 0) {
            // If it matched by name but sub-items were filtered out (shouldn't happen with logic above but for safety)
            // Actually, if matches is true, we want to keep all subitems?
            // The user simply wants the Parent status to reflect its Children.
            // However, filter logic creates a new subset. The status should logically reflect the *visible* items?
            // Or should it reflect the *absolute* status?
            // "unwrapKey" status should be "Partial" regardless of search.
            // So we should probably preprocess the data with derived statuses *before* filtering.
          }
          return newItem;
        }
        return null;
      })
      .filter(Boolean) as CoverageItem[];
  };

  // Better approach: Pre-process data to derive statuses, THEN filter.
  const processedData = COVERAGE_DATA.map(category => ({
    ...category,
    items: category.items.map(function processItem(item): CoverageItem {
      const newItem = { ...item };
      if (newItem.subItems && newItem.subItems.length > 0) {
        newItem.subItems = newItem.subItems.map(processItem);
        newItem.status = deriveStatus(newItem);
      }
      return newItem;
    }),
  }));

  const filterProcessedItems = (items: CoverageItem[]): CoverageItem[] => {
    return items
      .map(item => {
        const matches = item.name.toLowerCase().includes(search.toLowerCase());
        const subMatches = item.subItems
          ? filterProcessedItems(item.subItems)
          : [];

        if (matches || subMatches.length > 0) {
          return { ...item, subItems: subMatches };
        }
        return null;
      })
      .filter(Boolean) as CoverageItem[];
  };

  const StatusIcon = ({ status }: { status: CapabilityStatus }) => {
    switch (status) {
      case 'implemented':
        return <CheckCircle2 className="w-5 h-5 text-green-500" />;
      case 'missing':
        return <XCircle className="w-5 h-5 text-red-500" />;
      case 'partial':
        return <AlertTriangle className="w-5 h-5 text-yellow-500" />;
      case 'not-in-node':
        return <MinusCircle className="w-5 h-5 text-gray-400" />;
    }
  };

  const StatusLabel = ({ status }: { status: CapabilityStatus }) => {
    const labels: Record<CapabilityStatus, string> = {
      implemented: 'Implemented',
      missing: 'Missing',
      partial: 'Partial',
      'not-in-node': 'N/A',
    };
    return <span className="text-sm font-medium">{labels[status]}</span>;
  };

  const calculateStats = () => {
    let total = 0;
    let implemented = 0;
    let partial = 0;
    let missing = 0;

    const countItems = (items: CoverageItem[]) => {
      items.forEach(item => {
        if (item.subItems && item.subItems.length > 0) {
          countItems(item.subItems);
        } else {
          const status = item.status || 'missing';
          if (status === 'not-in-node') return;
          total++;
          if (status === 'implemented') implemented++;
          if (status === 'partial') partial++;
          if (status === 'missing') missing++;
        }
      });
    };

    processedData.forEach(category => countItems(category.items));

    return {
      total,
      implemented,
      partial,
      missing,
      implPercent: total > 0 ? Math.round((implemented / total) * 100) : 0,
      partPercent: total > 0 ? Math.round((partial / total) * 100) : 0,
      missPercent: total > 0 ? Math.round((missing / total) * 100) : 0,
    };
  };

  const stats = calculateStats();

  const filteredCategories = processedData
    .map(category => ({
      ...category,
      items: search ? filterProcessedItems(category.items) : category.items,
    }))
    .filter(category => category.items.length > 0);

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row gap-4 justify-between items-center bg-fd-secondary/20 p-2 rounded-lg border border-fd-border">
        <div className="flex gap-4 text-xs font-medium">
          <div className="flex items-center gap-2 text-green-600 dark:text-green-400">
            <CheckCircle2 className="w-4 h-4" />
            <span>Implemented: {stats.implPercent}%</span>
          </div>
          <div className="flex items-center gap-2 text-yellow-600 dark:text-yellow-400">
            <AlertTriangle className="w-4 h-4" />
            <span>Partial: {stats.partPercent}%</span>
          </div>
          <div className="flex items-center gap-2 text-red-600 dark:text-red-400">
            <XCircle className="w-4 h-4" />
            <span>Missing: {stats.missPercent}%</span>
          </div>
        </div>

        <div className="relative w-full sm:w-64">
          <input
            type="text"
            placeholder="Search API..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="w-full px-2 py-1 text-xs bg-fd-background rounded-md border border-fd-border focus:outline-none focus:ring-2 focus:ring-fd-primary"
          />
        </div>
      </div>

      {filteredCategories.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-12 text-center border border-dashed border-fd-border rounded-xl bg-fd-secondary/10">
          <div className="bg-fd-secondary/50 p-3 rounded-full mb-4">
            <SearchX className="w-6 h-6 text-fd-muted-foreground" />
          </div>
          <h3 className="text-lg font-semibold">No API found</h3>
          <p className="text-sm text-fd-muted-foreground mt-1">
            No results matching "
            <span className="font-medium text-fd-foreground">{search}</span>"
          </p>
          <button
            onClick={() => setSearch('')}
            className="mt-4 text-sm text-fd-primary hover:underline font-medium">
            Clear search
          </button>
        </div>
      ) : (
        filteredCategories.map(category => (
          <div
            key={category.title}
            className="bg-fd-card rounded-xl border border-fd-border overflow-hidden">
            <div className="px-6 py-4 bg-fd-card border-b border-fd-border sticky top-[var(--fd-nav-height)] z-10">
              <h3 className="font-semibold text-lg">{category.title}</h3>
              {category.description && (
                <p className="text-sm text-fd-muted-foreground mt-1">
                  {category.description}
                </p>
              )}
            </div>
            <div className="divide-y divide-fd-border/50">
              {category.items.map(item => (
                <div
                  key={item.name}
                  className="px-6 py-3 flex items-start justify-between hover:bg-fd-secondary/10 transition-colors">
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <code className="font-mono text-sm">{item.name}</code>
                      {item.note && (
                        <span className="text-xs px-2 py-0.5 rounded-full bg-fd-secondary text-fd-muted-foreground">
                          {item.note}
                        </span>
                      )}
                    </div>
                    {item.subItems && item.subItems.length > 0 && (
                      <div className="mt-2 ml-4 pl-4 border-l border-fd-border/50 space-y-2">
                        {item.subItems.map(sub => (
                          <div
                            key={sub.name}
                            className="flex items-center gap-2 text-sm text-fd-muted-foreground">
                            <StatusIcon status={sub.status || 'missing'} />
                            <span className="font-mono">{sub.name}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                  <div className="flex items-center gap-2 min-w-[120px] justify-end">
                    <StatusLabel status={item.status || 'missing'} />
                    <StatusIcon status={item.status || 'missing'} />
                  </div>
                </div>
              ))}
            </div>
          </div>
        ))
      )}
    </div>
  );
}
