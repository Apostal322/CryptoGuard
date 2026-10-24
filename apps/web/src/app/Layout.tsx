import { NavLink, Outlet } from "react-router-dom";

import { useStatus } from "./status";

function ModeBanner() {
  const { data, error } = useStatus();
  if (error) {
    return (
      <div role="alert" className="border-b border-critical/40 bg-critical/10 px-4 py-2 text-center text-sm">
        The CryptoGuard API is unreachable: {error.message}
      </div>
    );
  }
  if (!data) return null;
  if (data.mode === "demo") {
    return (
      <div role="status" className="border-b border-simulated/40 bg-simulated/10 px-4 py-2 text-center text-sm">
        <strong className="font-semibold text-simulated">Demo mode — simulated data.</strong>{" "}
        Every address, balance and finding shown is a fictional fixture, not Ethereum state.
      </div>
    );
  }
  if (!data.rpc_configured) {
    return (
      <div role="status" className="border-b border-review/40 bg-review/10 px-4 py-2 text-center text-sm">
        No Ethereum RPC endpoint is configured, so nothing can be analyzed. Set CRYPTOGUARD_RPC_URL,
        or restart the API with CRYPTOGUARD_MODE=demo for simulated data.
      </div>
    );
  }
  if (data.provider_error) {
    return (
      <div role="alert" className="border-b border-critical/40 bg-critical/10 px-4 py-2 text-center text-sm">
        RPC provider problem ({data.provider_error.code}): {data.provider_error.message}
      </div>
    );
  }
  return null;
}

const navClass = ({ isActive }: { isActive: boolean }) =>
  `rounded-md px-3 py-1.5 text-sm ${isActive ? "bg-surface-2 text-ink" : "text-muted hover:text-ink"}`;

export function Layout() {
  return (
    <div className="flex min-h-screen flex-col">
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-2">
        Skip to content
      </a>
      <ModeBanner />
      <header className="border-b border-line">
        <div className="mx-auto flex max-w-6xl items-center justify-between gap-4 px-4 py-3 sm:px-6">
          <NavLink to="/" className="flex items-baseline gap-2">
            <span className="text-base font-semibold tracking-tight">CryptoGuard</span>
            <span className="hidden text-xs text-muted sm:inline">Explainable wallet threat intelligence</span>
          </NavLink>
          <nav aria-label="Main" className="flex gap-1">
            <NavLink to="/" end className={navClass}>
              Dashboard
            </NavLink>
            <NavLink to="/replay" className={navClass}>
              Replay
            </NavLink>
            <NavLink to="/settings" className={navClass}>
              Settings
            </NavLink>
          </nav>
        </div>
      </header>
      <main id="main" className="mx-auto w-full max-w-6xl flex-1 px-4 py-8 sm:px-6">
        <Outlet />
      </main>
      <footer className="border-t border-line px-4 py-4 text-center text-xs text-faint">
        Read-only. CryptoGuard never asks for private keys or seed phrases and never signs
        transactions.
      </footer>
    </div>
  );
}
