// Shared between DevLoginScreen (sets it) and App.tsx (reads + clears it on mount) so a
// local dev auto-login can land on a specific tab (Early Warnings) without a real router.
// Session-only by design: it should only ever affect the very next render after a
// dev-login, never a later reload.
export const INITIAL_TAB_STORAGE_KEY = "aegis_initial_tab";
