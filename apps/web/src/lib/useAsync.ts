import { useCallback, useEffect, useRef, useState } from "react";

import { ApiError } from "../api/client";

export interface AsyncState<T> {
  data: T | null;
  error: ApiError | null;
  loading: boolean;
  run: () => Promise<void>;
}

/**
 * Runs ``load`` (immediately when ``auto``), tracking loading/error state. Stale results from
 * a superseded call are ignored, so fast navigation cannot show another wallet's data.
 */
export function useAsync<T>(load: () => Promise<T>, deps: unknown[], auto = true): AsyncState<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [loading, setLoading] = useState(auto);
  const generation = useRef(0);

  // ``load`` is re-created on every render; ``deps`` decide when it really changed.
  const stableLoad = useCallback(load, deps);

  const run = useCallback(async () => {
    const mine = ++generation.current;
    setLoading(true);
    setError(null);
    try {
      const result = await stableLoad();
      if (mine === generation.current) setData(result);
    } catch (cause) {
      if (mine !== generation.current) return;
      setError(
        cause instanceof ApiError
          ? cause
          : new ApiError(0, { code: "client_error", message: "Unexpected client error.", details: {} }),
      );
    } finally {
      if (mine === generation.current) setLoading(false);
    }
  }, [stableLoad]);

  useEffect(() => {
    setData(null);
    if (auto) void run();
    else setLoading(false);
  }, [run, auto]);

  return { data, error, loading, run };
}
