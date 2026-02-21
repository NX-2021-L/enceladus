/**
 * RecentItemsDisplay.tsx — Display recently created and updated feed items
 *
 * Shows 3 most recently created items and 2 most recently updated items
 * (excluding those in the created list) with FLIP animations on changes.
 */

import { useMemo } from "react";
import { useNavigate } from "react-router-dom";
import type { FeedItem } from "../../types/feed";
import { RECORD_TYPE_COLORS } from "../../lib/constants";
import { formatTimeSince } from "../../lib/timeFormat";
import { AnimatedList } from "./AnimatedList";

interface RecentItemsDisplayProps {
  items: FeedItem[];
}

interface RecentItemDisplay {
  _id: string;
  _type: string;
  displayTitle: string;
  timeAgo: string;
  item: FeedItem;
}

const RECENT_CREATED_COUNT = 3;
const RECENT_UPDATED_COUNT = 2;

/**
 * Helper to get display title from FeedItem
 */
function getItemTitle(item: FeedItem): string {
  switch (item._type) {
    case "task":
      return item.data.title || item._id;
    case "issue":
      return item.data.title || item._id;
    case "feature":
      return item.data.title || item._id;
  }
}

/**
 * Helper to parse ISO date string to milliseconds
 */
function parseDate(dateStr: string | null): number {
  if (!dateStr) return 0;
  try {
    return new Date(dateStr).getTime();
  } catch {
    return 0;
  }
}

export function RecentItemsDisplay({ items }: RecentItemsDisplayProps) {
  const navigate = useNavigate();

  const { recentCreated, recentUpdated } = useMemo(() => {
    // Sort by created_at descending and take top 3
    const created = [...items]
      .filter((item) => item._created_at !== null)
      .sort((a, b) => parseDate(b._created_at) - parseDate(a._created_at))
      .slice(0, RECENT_CREATED_COUNT)
      .map(
        (item): RecentItemDisplay => ({
          _id: item._id,
          _type: item._type,
          displayTitle: getItemTitle(item),
          timeAgo: formatTimeSince(parseDate(item._created_at)),
          item,
        })
      );

    // Get IDs of created items to exclude them
    const createdIds = new Set(created.map((i) => i._id));

    // Sort by updated_at descending, exclude created items, take top 2
    const updated = [...items]
      .filter((item) => item._updated_at !== null && !createdIds.has(item._id))
      .sort((a, b) => parseDate(b._updated_at) - parseDate(a._updated_at))
      .slice(0, RECENT_UPDATED_COUNT)
      .map(
        (item): RecentItemDisplay => ({
          _id: item._id,
          _type: item._type,
          displayTitle: getItemTitle(item),
          timeAgo: formatTimeSince(parseDate(item._updated_at)),
          item,
        })
      );

    return { recentCreated: created, recentUpdated: updated };
  }, [items]);

  // Empty state
  if (recentCreated.length === 0 && recentUpdated.length === 0) {
    return null;
  }

  const handleItemClick = (itemId: string, type: string) => {
    // Navigate to detail page: /enceladus/{type}/{id}
    navigate(`/enceladus/${type}/${itemId}`);
  };

  return (
    <div className="mb-6 space-y-4">
      {/* Recent Items (Created) */}
      {recentCreated.length > 0 && (
        <div>
          <h3 className="text-sm font-semibold text-slate-300 mb-2">
            Recent Items:
          </h3>
          <AnimatedList
            items={recentCreated}
            renderItem={(display) => (
              <RecentItemCard
                display={display}
                onClick={() => handleItemClick(display._id, display._type)}
              />
            )}
            className="space-y-2"
          />
        </div>
      )}

      {/* Recent Updates */}
      {recentUpdated.length > 0 && (
        <div>
          <h3 className="text-sm font-semibold text-slate-300 mb-2">
            Recent Updates:
          </h3>
          <AnimatedList
            items={recentUpdated}
            renderItem={(display) => (
              <RecentItemCard
                display={display}
                onClick={() => handleItemClick(display._id, display._type)}
              />
            )}
            className="space-y-2"
          />
        </div>
      )}
    </div>
  );
}

interface RecentItemCardProps {
  display: RecentItemDisplay;
  onClick: () => void;
}

function RecentItemCard({ display, onClick }: RecentItemCardProps) {
  const typeColor = RECORD_TYPE_COLORS[display._type] || "bg-slate-500";
  const titleDisplay = display.displayTitle.length > 45
    ? display.displayTitle.substring(0, 42) + "..."
    : display.displayTitle;

  return (
    <button
      onClick={onClick}
      className="w-full text-left p-2 rounded border border-slate-700 bg-slate-800/50 hover:bg-slate-700 transition-colors"
      data-item-id={display._id}
    >
      <div className="flex items-start gap-3">
        {/* Type indicator dot */}
        <div className={`w-2 h-2 rounded-full flex-shrink-0 mt-1.5 ${typeColor}`} />

        <div className="flex-1 min-w-0">
          {/* Item ID */}
          <div className="text-xs font-mono text-slate-400">{display._id}</div>

          {/* Title */}
          <div className="text-sm text-slate-100 truncate">
            {titleDisplay}
          </div>
        </div>

        {/* Time badge */}
        <div className="text-xs text-slate-500 flex-shrink-0 ml-2">
          {display.timeAgo}
        </div>
      </div>
    </button>
  );
}
