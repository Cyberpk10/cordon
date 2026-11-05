import Image from "next/image";
import { ImageOff } from "lucide-react";
import WindowChrome from "@/components/ui/WindowChrome";

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
    <div className="card overflow-hidden shadow-2xl shadow-black/40">
      <WindowChrome />
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
