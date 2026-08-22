import { useEffect, useRef } from "react";

/** Calls `callback` every `delayMs`, always invoking the latest closure without resetting
 * the timer on every render (the standard ref-based interval pattern) — pass `null` for
 * `delayMs` to pause. Dev-friendly polling helper: components that call this simply unmount
 * (stopping the interval for free) when the user navigates away, since this app has no
 * router keeping views alive off-screen. */
export function useInterval(callback: () => void, delayMs: number | null): void {
  const savedCallback = useRef(callback);

  useEffect(() => {
    savedCallback.current = callback;
  }, [callback]);

  useEffect(() => {
    if (delayMs === null) return;
    const id = setInterval(() => savedCallback.current(), delayMs);
    return () => clearInterval(id);
  }, [delayMs]);
}
