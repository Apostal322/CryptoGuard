import { createContext, useContext, type ReactNode } from "react";

import { api } from "../api/client";
import type { StatusResponse } from "../api/types";
import { useAsync, type AsyncState } from "../lib/useAsync";

const StatusContext = createContext<AsyncState<StatusResponse> | null>(null);

/** Loads /status once; every page reads mode (real vs demo) and provider health from here. */
export function StatusProvider({ children }: { children: ReactNode }) {
  const state = useAsync(() => api.status(), []);
  return <StatusContext.Provider value={state}>{children}</StatusContext.Provider>;
}

export function useStatus(): AsyncState<StatusResponse> {
  const value = useContext(StatusContext);
  if (!value) throw new Error("useStatus must be used inside StatusProvider");
  return value;
}
