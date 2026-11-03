import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import clsx from "clsx";
import { AlertTriangle, CheckCircle2, Info, X, XCircle, type LucideIcon } from "lucide-react";

export type ToastTone = "success" | "danger" | "warning" | "info";

export interface ToastOptions {
  title: string;
  description?: string;
  tone?: ToastTone;
  /** ms before auto-dismiss; errors stay a little longer by default. */
  duration?: number;
}

interface ToastItem extends Required<Omit<ToastOptions, "description">> {
  id: number;
  description?: string;
}

const ToastContext = createContext<((options: ToastOptions) => void) | null>(null);

const TONE: Record<ToastTone, { icon: LucideIcon; iconClass: string }> = {
  success: { icon: CheckCircle2, iconClass: "text-success" },
  danger: { icon: XCircle, iconClass: "text-danger" },
  warning: { icon: AlertTriangle, iconClass: "text-warning" },
  info: { icon: Info, iconClass: "text-accent" },
};

function ToastView({ toast, onDismiss }: { toast: ToastItem; onDismiss: (id: number) => void }) {
  const { icon: Icon, iconClass } = TONE[toast.tone];
  const timer = useRef<number>();
  const start = useCallback(() => {
    timer.current = window.setTimeout(() => onDismiss(toast.id), toast.duration);
  }, [onDismiss, toast.duration, toast.id]);
  const stop = () => window.clearTimeout(timer.current);

  useEffect(() => {
    start();
    return stop;
  }, [start]);

  return (
    <div
      // Errors interrupt; everything else waits politely.
      role={toast.tone === "danger" ? "alert" : "status"}
      onMouseEnter={stop}
      onMouseLeave={start}
      onFocus={stop}
      onBlur={start}
      className="pointer-events-auto flex w-full items-start gap-3 rounded-card border border-line-strong bg-surface-panel px-4 py-3 shadow-2xl shadow-black/40 motion-safe:animate-[toast-in_150ms_ease-out]"
    >
      <Icon aria-hidden="true" className={clsx("mt-0.5 h-4 w-4 shrink-0", iconClass)} />
      <div className="min-w-0 flex-1">
        <p className="text-sm font-semibold text-fg">{toast.title}</p>
        {toast.description && <p className="mt-0.5 text-sm text-fg-secondary">{toast.description}</p>}
      </div>
      <button
        type="button"
        onClick={() => onDismiss(toast.id)}
        aria-label="Dismiss notification"
        className="-mr-1 flex h-6 w-6 shrink-0 items-center justify-center rounded-md text-fg-muted transition-colors duration-150 hover:bg-surface-raised hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
      >
        <X aria-hidden="true" className="h-3.5 w-3.5" />
      </button>
    </div>
  );
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const nextId = useRef(0);

  const dismiss = useCallback((id: number) => {
    setToasts((current) => current.filter((t) => t.id !== id));
  }, []);

  const show = useCallback((options: ToastOptions) => {
    const tone = options.tone ?? "success";
    const id = ++nextId.current;
    setToasts((current) => [
      ...current.slice(-3),
      { id, tone, title: options.title, description: options.description, duration: options.duration ?? (tone === "danger" ? 7000 : 4000) },
    ]);
  }, []);

  const value = useMemo(() => show, [show]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div
        aria-label="Notifications"
        className="pointer-events-none fixed inset-x-4 bottom-4 z-50 flex flex-col items-end gap-2 sm:left-auto sm:right-6 sm:w-96"
      >
        {toasts.map((toast) => (
          <ToastView key={toast.id} toast={toast} onDismiss={dismiss} />
        ))}
      </div>
    </ToastContext.Provider>
  );
}

/** `const toast = useToast(); toast({ title: "Copied" })`. */
export function useToast() {
  const context = useContext(ToastContext);
  if (!context) throw new Error("useToast must be used inside <ToastProvider>");
  return context;
}
