import { createContext, useContext, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { CalendarRange } from "lucide-react";

interface TopBarSlots {
  /** Right-hand action area (filters, primary buttons). */
  actions: HTMLElement | null;
  /** Short context after the subtitle (e.g. the effective reporting period). */
  context: HTMLElement | null;
}

/** The top bar's slots, provided by AppShell. */
export const TopBarSlotsContext = createContext<TopBarSlots>({ actions: null, context: null });

/** Renders its children into the AppShell top bar (right side) instead of in place.
 * A screen keeps owning the state its filters/buttons drive — only where they're drawn
 * moves — so the top bar can host per-screen controls without lifting any state.
 * Unmounts with the screen, so a hidden sub-tab never leaves controls behind. */
export default function PageActions({ children }: { children: ReactNode }) {
  const { actions } = useContext(TopBarSlotsContext);
  return actions ? createPortal(children, actions) : null;
}

/** Short inline context appended to the top-bar subtitle, e.g. the reporting period. */
export function PageContext({ children }: { children: ReactNode }) {
  const { context } = useContext(TopBarSlotsContext);
  return context
    ? createPortal(
        <>
          <CalendarRange aria-hidden="true" className="h-3.5 w-3.5" />
          <span>{children}</span>
        </>,
        context
      )
    : null;
}
