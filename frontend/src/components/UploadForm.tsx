import { useRef, useState } from "react";
import { ScanSearch } from "lucide-react";
import { Button } from "./ui";

interface UploadFormProps {
  onSubmit: (file: File) => void;
  isLoading: boolean;
}

export default function UploadForm({ onSubmit, isLoading }: UploadFormProps) {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    setSelectedFile(event.target.files?.[0] ?? null);
  };

  const handleSubmit = (event: React.FormEvent) => {
    event.preventDefault();
    if (selectedFile) {
      onSubmit(selectedFile);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-4 sm:flex-row sm:items-center">
      <input
        ref={inputRef}
        type="file"
        accept=".eml"
        aria-label="Email file (.eml)"
        onChange={handleFileChange}
        className="block w-full flex-1 cursor-pointer rounded-control border border-line-strong bg-surface-raised text-sm text-fg-secondary file:mr-4 file:cursor-pointer file:rounded-md file:border-0 file:bg-line-strong file:px-4 file:py-2 file:text-sm file:font-semibold file:text-fg hover:file:bg-line"
      />
      <Button
        type="submit"
        variant="primary"
        icon={ScanSearch}
        disabled={!selectedFile}
        loading={isLoading}
        loadingText="Analyzing…"
      >
        Analyze Email
      </Button>
    </form>
  );
}
