import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useId,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { AlertTriangle, Info, X } from "lucide-react";
import clsx from "clsx";
import Button from "./Button";

export interface ModalProps {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  description?: ReactNode;
  /** "alertdialog" for confirmations that interrupt a destructive action. */
  role?: "dialog" | "alertdialog";
  /** Footer buttons, right-aligned. */
  footer?: ReactNode;
  icon?: ReactNode;
  children?: ReactNode;
  className?: string;
}

/** Built on the native <dialog> + showModal(): the browser provides the focus trap, makes
 * the rest of the page inert, puts it in the top layer, and turns Escape into a cancel.
 * Focus returns to whatever opened it. Clicking the backdrop also closes it. */
export function Modal({
  open,
  onClose,
  title,
  description,
  role = "dialog",
  footer,
  icon,
  children,
  className,
}: ModalProps) {
  const ref = useRef<HTMLDialogElement>(null);
  const returnFocus = useRef<HTMLElement | null>(null);
  const titleId = useId();
  const descId = useId();

  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    if (open && !dialog.open) {
      returnFocus.current = document.activeElement as HTMLElement | null;
      dialog.showModal();
    } else if (!open && dialog.open) {
      dialog.close();
    }
  }, [open]);

  // Restore focus once the dialog is gone (also covers unmount while open).
  useEffect(() => {
    if (open) return;
    const target = returnFocus.current;
    returnFocus.current = null;
    if (target && document.contains(target)) target.focus();
  }, [open]);

  return (
    <dialog
      ref={ref}
      role={role}
      aria-labelledby={titleId}
      aria-describedby={description ? descId : undefined}
      // Escape: let React own the state instead of the dialog closing itself.
      onCancel={(event) => {
        event.preventDefault();
        onClose();
      }}
      // A click whose target is the <dialog> itself landed on the backdrop.
      onClick={(event) => {
        if (event.target === ref.current) onClose();
      }}
      // The native modal keeps the page inert but lets Tab escape to the browser chrome
      // after the last control; wrap instead, so keyboard focus cycles within the dialog.
      onKeyDown={(event) => {
        if (event.key !== "Tab" || !ref.current) return;
        const focusable = [
          ...ref.current.querySelectorAll<HTMLElement>(
            'button:not(:disabled), [href], input:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex]:not([tabindex="-1"])'
          ),
        ];
        if (focusable.length === 0) return;
        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault();
          last.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first.focus();
        }
      }}
      className={clsx(
        "m-auto w-[calc(100%-2rem)] max-w-md rounded-card border border-line-strong bg-surface-panel p-0 text-fg shadow-2xl shadow-black/50",
        "backdrop:bg-black/60 backdrop:backdrop-blur-[2px]",
        "open:motion-safe:animate-[fade-in-up_150ms_ease-out]",
        className
      )}
    >
      {open && (
        <div className="flex flex-col">
          <div className="flex items-start gap-3 px-5 pt-5">
            {icon}
            <div className="min-w-0 flex-1">
              <h2 id={titleId} className="text-base font-semibold text-fg">
                {title}
              </h2>
              {description && (
                <p id={descId} className="mt-1 text-sm text-fg-secondary">
                  {description}
                </p>
              )}
            </div>
            <button
              type="button"
              onClick={onClose}
              aria-label="Close"
              className="-mr-1 -mt-1 flex h-8 w-8 shrink-0 items-center justify-center rounded-md text-fg-muted transition-colors duration-150 hover:bg-surface-raised hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            >
              <X aria-hidden="true" className="h-4 w-4" />
            </button>
          </div>
          {children && <div className="px-5 pt-4">{children}</div>}
          {footer && (
            <div className="mt-5 flex flex-col-reverse gap-2 border-t border-line px-5 py-4 sm:flex-row sm:justify-end">
              {footer}
            </div>
          )}
        </div>
      )}
    </dialog>
  );
}

export interface ConfirmOptions {
  title: string;
  description?: ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  /** "danger" for destructive/irreversible actions. */
  tone?: "danger" | "default";
}

type Pending = ConfirmOptions & { resolve: (ok: boolean) => void };

const ConfirmContext = createContext<((options: ConfirmOptions) => Promise<boolean>) | null>(null);

/** App-wide confirmation dialog. `await confirm({...})` resolves true/false — a drop-in,
 * accessible replacement for window.confirm(). */
export function ConfirmProvider({ children }: { children: ReactNode }) {
  const [pending, setPending] = useState<Pending | null>(null);
  const cancelRef = useRef<HTMLButtonElement>(null);

  const confirm = useCallback(
    (options: ConfirmOptions) => new Promise<boolean>((resolve) => setPending({ ...options, resolve })),
    []
  );

  const settle = (ok: boolean) => {
    pending?.resolve(ok);
    setPending(null);
  };

  // Destructive confirms start on Cancel, so a stray Enter never deletes anything.
  useEffect(() => {
    if (pending) cancelRef.current?.focus();
  }, [pending]);

  const danger = pending?.tone === "danger";

  return (
    <ConfirmContext.Provider value={confirm}>
      {children}
      <Modal
        open={Boolean(pending)}
        onClose={() => settle(false)}
        role="alertdialog"
        title={pending?.title}
        description={pending?.description}
        icon={
          pending && (
            <span
              aria-hidden="true"
              className={clsx(
                "flex h-9 w-9 shrink-0 items-center justify-center rounded-full border",
                danger ? "border-danger/35 bg-danger/10 text-danger" : "border-accent/30 bg-accent/10 text-accent"
              )}
            >
              {danger ? <AlertTriangle className="h-4 w-4" /> : <Info className="h-4 w-4" />}
            </span>
          )
        }
        footer={
          pending && (
            <>
              <Button ref={cancelRef} onClick={() => settle(false)}>
                {pending.cancelLabel ?? "Cancel"}
              </Button>
              <Button variant={danger ? "danger" : "primary"} onClick={() => settle(true)}>
                {pending.confirmLabel ?? "Confirm"}
              </Button>
            </>
          )
        }
      />
    </ConfirmContext.Provider>
  );
}

export function useConfirm() {
  const context = useContext(ConfirmContext);
  if (!context) throw new Error("useConfirm must be used inside <ConfirmProvider>");
  return context;
}
