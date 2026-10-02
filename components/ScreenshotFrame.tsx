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
    <div className="overflow-hidden rounded-xl border border-white/10 bg-navy-900 shadow-2xl shadow-black/40">
      <div className="flex items-center gap-1.5 border-b border-white/10 bg-navy-800 px-4 py-3">
        <span className="h-2.5 w-2.5 rounded-full bg-white/15" />
        <span className="h-2.5 w-2.5 rounded-full bg-white/15" />
        <span className="h-2.5 w-2.5 rounded-full bg-white/15" />
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
          className={`flex w-full ${aspectClass} flex-col items-center justify-center gap-3 border-2 border-dashed border-white/10 bg-navy-950/60 px-6 text-center`}
          aria-label={`Placeholder for missing screenshot: ${filename}`}
        >
          <ImageOff className="h-6 w-6 text-slate-600" />
          <p className="text-sm font-medium text-slate-400">{alt}</p>
          <p className="font-mono text-xs text-slate-600">
            public/screenshots/{filename}
          </p>
        </div>
      )}
    </div>
  );
}
