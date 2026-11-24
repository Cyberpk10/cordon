import { useCallback, useEffect, useRef, useState } from "react";
import { Bell } from "lucide-react";
import { getNotifications, markAllNotificationsRead } from "../../api/client";
import type { NotificationList } from "../../types/analysis";

const POLL_MS = 60_000;

/** In-app notifications from Cordon's autonomy engine (flagged mail, approvals needed). */
export default function NotificationBell({ onOpenCases }: { onOpenCases: () => void }) {
  const [data, setData] = useState<NotificationList | null>(null);
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  const load = useCallback(() => {
    getNotifications()
      .then(setData)
      .catch(() => undefined); // a bell must never break the shell
  }, []);

  useEffect(() => {
    load();
    const id = window.setInterval(load, POLL_MS);
    return () => window.clearInterval(id);
  }, [load]);

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const toggle = () => {
    const next = !open;
    setOpen(next);
    if (next && data && data.unread > 0) {
      markAllNotificationsRead()
        .then((d) => setData({ ...d, items: data.items }))
        .catch(() => undefined);
    }
  };

  const unread = data?.unread ?? 0;

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        onClick={toggle}
        aria-label={unread ? `Notifications, ${unread} unread` : "Notifications"}
        aria-expanded={open}
        className="relative flex h-9 w-9 items-center justify-center rounded-lg text-fg-secondary transition-colors duration-150 hover:bg-surface-raised hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
      >
        <Bell aria-hidden="true" className="h-5 w-5" />
        {unread > 0 && (
          <span className="absolute right-1 top-1 min-w-4 rounded-full bg-danger px-1 text-center text-[10px] font-semibold leading-4 text-white">
            {unread > 9 ? "9+" : unread}
          </span>
        )}
      </button>
      {open && (
        <div className="absolute right-0 z-30 mt-2 w-80 max-w-[calc(100vw-2rem)] rounded-control border border-line bg-surface-panel shadow-lg">
          <p className="border-b border-line px-4 py-2 text-sm font-semibold text-fg">Notifications</p>
          {data && data.items.length > 0 ? (
            <ul className="max-h-96 overflow-y-auto">
              {data.items.map((n) => (
                <li key={n.id}>
                  <button
                    type="button"
                    onClick={() => {
                      setOpen(false);
                      onOpenCases();
                    }}
                    className="block w-full px-4 py-3 text-left hover:bg-surface-raised focus-visible:bg-surface-raised focus-visible:outline-none"
                  >
                    <p className="text-sm font-medium text-fg">{n.title}</p>
                    <p className="mt-0.5 text-xs text-fg-secondary">{n.body}</p>
                    <p className="mt-1 text-[11px] text-fg-muted">{new Date(n.created_at).toLocaleString()}</p>
                  </button>
                </li>
              ))}
            </ul>
          ) : (
            <p className="px-4 py-6 text-center text-sm text-fg-muted">Nothing new.</p>
          )}
        </div>
      )}
    </div>
  );
}
