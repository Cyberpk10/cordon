interface AegisLogoProps {
  className?: string;
}

// Cordon's "C" mark, matching the aegis-site marketing project's public/cordon-logo.png,
// reused here for product/marketing brand consistency.
export default function AegisLogo({ className }: AegisLogoProps) {
  return (
    <img
      src="/cordon-logo.png"
      alt="Cordon"
      className={`rounded-[7px] ${className ?? ""}`}
    />
  );
}
