/** "Oct 4 – Nov 3, 2026" (or "Dec 1, 2025 – Jan 3, 2026" across years). Used for the
 * effective reporting period shown in the top bar. */
export function formatPeriod(start: string, end: string): string {
  const s = new Date(start);
  const e = new Date(end);
  const sameYear = s.getFullYear() === e.getFullYear();
  const startText = s.toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    ...(sameYear ? {} : { year: "numeric" }),
  });
  const endText = e.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
  return `${startText} – ${endText}`;
}
