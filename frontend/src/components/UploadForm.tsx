import { useEffect, useId, useRef, useState, type DragEvent } from "react";
import clsx from "clsx";
import { FileText, ScanSearch, UploadCloud, X } from "lucide-react";
import { Button } from "./ui";

interface UploadFormProps {
  onSubmit: (file: File) => void;
  isLoading: boolean;
}

// Mirrors the backend's settings.max_upload_bytes (10 MiB) so an oversized file is caught
// before upload; the server still enforces the real limit.
const MAX_BYTES = 10 * 1024 * 1024;

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function validate(file: File): string | null {
  if (!file.name.toLowerCase().endsWith(".eml")) {
    return `“${file.name}” isn’t an .eml file. Save the message as .eml from your mail client, or use Paste instead.`;
  }
  if (file.size > MAX_BYTES) {
    return `“${file.name}” is ${formatBytes(file.size)} — the limit is 10 MB.`;
  }
  return null;
}

export default function UploadForm({ onSubmit, isLoading }: UploadFormProps) {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [fileError, setFileError] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const dragDepth = useRef(0);
  const inputId = useId();
  const hintId = `${inputId}-hint`;
  const errorId = `${inputId}-error`;

  // A file dropped just outside the zone would otherwise make the browser navigate away
  // to display it, losing the page. Swallow stray drops while this form is mounted.
  useEffect(() => {
    const prevent = (event: globalThis.DragEvent) => {
      if (event.dataTransfer?.types.includes("Files")) event.preventDefault();
    };
    window.addEventListener("dragover", prevent);
    window.addEventListener("drop", prevent);
    return () => {
      window.removeEventListener("dragover", prevent);
      window.removeEventListener("drop", prevent);
    };
  }, []);

  const accept = (file: File | undefined) => {
    if (!file) return;
    const problem = validate(file);
    setFileError(problem);
    setSelectedFile(problem ? null : file);
  };

  const clear = () => {
    setSelectedFile(null);
    setFileError(null);
    if (inputRef.current) inputRef.current.value = "";
    inputRef.current?.focus();
  };

  const onDragEnter = (event: DragEvent) => {
    event.preventDefault();
    dragDepth.current += 1;
    setIsDragging(true);
  };
  const onDragLeave = (event: DragEvent) => {
    event.preventDefault();
    dragDepth.current = Math.max(0, dragDepth.current - 1);
    if (dragDepth.current === 0) setIsDragging(false);
  };
  const onDrop = (event: DragEvent) => {
    event.preventDefault();
    dragDepth.current = 0;
    setIsDragging(false);
    accept(event.dataTransfer.files?.[0]);
  };

  const handleSubmit = (event: React.FormEvent) => {
    event.preventDefault();
    if (selectedFile) {
      onSubmit(selectedFile);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-4">
      <label
        htmlFor={inputId}
        onDragEnter={onDragEnter}
        onDragOver={(event) => event.preventDefault()}
        onDragLeave={onDragLeave}
        onDrop={onDrop}
        className={clsx(
          "group flex cursor-pointer flex-col items-center justify-center gap-3 rounded-card border-2 border-dashed px-6 py-10 text-center",
          "transition-colors duration-150",
          "has-[:focus-visible]:border-accent has-[:focus-visible]:ring-2 has-[:focus-visible]:ring-accent/30",
          isDragging
            ? "border-accent bg-accent/10"
            : fileError
              ? "border-danger/50 bg-danger/5"
              : "border-line-strong bg-surface-panel hover:border-accent/60 hover:bg-accent/5"
        )}
      >
        <input
          ref={inputRef}
          id={inputId}
          type="file"
          accept=".eml,message/rfc822"
          aria-describedby={fileError ? `${hintId} ${errorId}` : hintId}
          aria-invalid={fileError ? true : undefined}
          onChange={(event) => accept(event.target.files?.[0])}
          className="sr-only"
        />
        <span
          aria-hidden="true"
          className={clsx(
            "flex h-12 w-12 items-center justify-center rounded-full border transition-colors duration-150",
            isDragging
              ? "border-accent/50 bg-accent/15 text-accent"
              : "border-line-strong bg-surface-raised text-fg-secondary group-hover:text-accent"
          )}
        >
          <UploadCloud className="h-6 w-6" />
        </span>
        <span className="text-sm text-fg">
          {isDragging ? (
            <span className="font-semibold">Release to add this email</span>
          ) : (
            <>
              <span className="font-semibold">Drop an email here</span>
              <span className="text-fg-secondary">, or </span>
              <span className="font-semibold text-accent underline-offset-2 group-hover:underline">
                browse
              </span>
            </>
          )}
        </span>
        <span id={hintId} className="text-xs text-fg-muted">
          .eml files up to 10 MB
        </span>
      </label>

      {fileError && (
        <p id={errorId} role="alert" className="text-sm text-danger">
          {fileError}
        </p>
      )}

      <div className="flex flex-wrap items-center gap-3">
        {selectedFile && (
          <div className="flex min-w-0 flex-1 items-center gap-3 rounded-control border border-line bg-surface-panel px-3 py-2">
            <FileText aria-hidden="true" className="h-4 w-4 shrink-0 text-accent" />
            <div className="min-w-0 flex-1">
              <p className="truncate text-sm font-semibold text-fg" title={selectedFile.name}>
                {selectedFile.name}
              </p>
              <p className="text-xs text-fg-muted">{formatBytes(selectedFile.size)}</p>
            </div>
            <button
              type="button"
              onClick={clear}
              disabled={isLoading}
              aria-label={`Remove ${selectedFile.name}`}
              className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md text-fg-muted transition-colors duration-150 hover:bg-surface-raised hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:opacity-50"
            >
              <X aria-hidden="true" className="h-4 w-4" />
            </button>
          </div>
        )}
        <Button
          type="submit"
          variant="primary"
          icon={ScanSearch}
          disabled={!selectedFile}
          loading={isLoading}
          loadingText="Analyzing…"
          className={selectedFile ? undefined : "self-start"}
        >
          Analyze Email
        </Button>
      </div>
    </form>
  );
}
