import type { ReactNode } from "react";

/**
 * The one section-headline scale used across the site: Space Grotesk h2 at 3xl/4xl with an
 * optional lede underneath. Spacing to the section's content is owned by the caller.
 */
export default function SectionHeading({
  title,
  lede,
  align = "center",
  icon,
}: {
  title: ReactNode;
  lede?: ReactNode;
  align?: "center" | "left";
  icon?: ReactNode;
}) {
  const centered = align === "center";
  return (
    <>
      <h2
        className={`text-3xl font-semibold tracking-tight text-fg sm:text-4xl ${
          icon ? `flex items-center gap-3 ${centered ? "justify-center" : ""}` : ""
        }`}
      >
        {icon}
        {title}
      </h2>
      {lede && (
        <p
          className={`mt-4 text-lg leading-relaxed text-fg-secondary ${
            centered ? "mx-auto max-w-2xl" : ""
          }`}
        >
          {lede}
        </p>
      )}
    </>
  );
}
