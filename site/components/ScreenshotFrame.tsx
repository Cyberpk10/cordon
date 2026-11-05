import Image from "next/image";
import { ImageOff } from "lucide-react";

type ScreenshotFrameProps = {
  src: string | null;
  alt: string;
  filename: string;
  aspectClass?: string;
  priority?: boolean;
};

/**
 * Clean "browser chrome" frame for a real product screenshot. Renders the actual image when
 * present (via `fill` + object-contain, so an unknown real aspect ratio is never stretched —
 * we don't control the source dimensions); otherwise renders an honest, clearly-labeled
 * placeholder — never a fabricated mockup — so it's obvious where the file needs to go.
 */
export default function ScreenshotFrame({
  src,
  alt,
  filename,
  aspectClass = "aspect-[16/10]",
  priority = false,
}: ScreenshotFrameProps) {
  return (
    <div className="overflow-hidden rounded-card border border-line bg-surface-panel shadow-2xl shadow-black/40 transition-all duration-300 hover:border-line-strong hover:shadow-black/60">
      <div className="flex items-center gap-1.5 border-b border-line bg-surface-raised px-4 py-3">
        <span className="h-2.5 w-2.5 rounded-full bg-line-strong" />
        <span className="h-2.5 w-2.5 rounded-full bg-line-strong" />
        <span className="h-2.5 w-2.5 rounded-full bg-line-strong" />
      </div>
      {src ? (
        <div className={`relative w-full ${aspectClass}`}>
          <Image
            src={src}
            alt={alt}
            fill
            priority={priority}
            className="object-contain"
            sizes="(min-width: 1024px) 640px, 100vw"
          />
        </div>
      ) : (
        <div
          className={`flex w-full ${aspectClass} flex-col items-center justify-center gap-3 border-2 border-dashed border-line bg-surface-page/60 px-6 text-center`}
          aria-label={`Placeholder for missing screenshot: ${filename}`}
        >
          <ImageOff className="h-6 w-6 text-fg-muted" />
          <p className="text-sm font-normal text-fg-secondary">{alt}</p>
          <p className="font-mono text-xs text-fg-muted">
            public/screenshots/{filename}
          </p>
        </div>
      )}
    </div>
  );
}
