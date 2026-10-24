import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { createBrowserRouter, Link, RouterProvider } from "react-router-dom";

import "./index.css";
import { Layout } from "./app/Layout";
import { StatusProvider } from "./app/status";
import { Dashboard } from "./pages/Dashboard";
import { Replay } from "./pages/Replay";
import { Settings } from "./pages/Settings";
import { WalletPage } from "./pages/wallet/WalletPage";

/** Replaces the router's developer error page; never shows stack traces to users. */
function AppError() {
  return (
    <div className="mx-auto max-w-xl px-4 py-16 text-sm">
      <h1 className="mb-2 text-lg font-semibold">Something went wrong in the interface</h1>
      <p className="mb-4 text-muted">
        No data was changed. Reload the page; if it keeps happening, check the browser console.
      </p>
      <a className="text-accent hover:underline" href="/">
        Back to the dashboard
      </a>
    </div>
  );
}

function NotFound() {
  return (
    <div className="text-sm">
      <p className="mb-2">This page does not exist.</p>
      <Link className="text-accent hover:underline" to="/">
        Back to the dashboard
      </Link>
    </div>
  );
}

export const routes = [
  {
    path: "/",
    element: <Layout />,
    errorElement: <AppError />,
    children: [
      { index: true, element: <Dashboard /> },
      { path: "wallet/:address", element: <WalletPage /> },
      { path: "replay", element: <Replay /> },
      { path: "settings", element: <Settings /> },
      { path: "*", element: <NotFound /> },
    ],
  },
];

const root = document.getElementById("root");
if (root) {
  createRoot(root).render(
    <StrictMode>
      <StatusProvider>
        <RouterProvider router={createBrowserRouter(routes)} />
      </StatusProvider>
    </StrictMode>,
  );
}
