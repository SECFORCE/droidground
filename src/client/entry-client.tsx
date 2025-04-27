// Package imports
import { createRoot, hydrateRoot } from "react-dom/client";

// Local imports
import '@client/index.css'
import { App } from '@client/App'

const container = document.getElementById("app");

const FullApp = () => (
    <App />
);

if (import.meta.hot || !container?.innerText) {
  const root = createRoot(container!);
  root.render(<FullApp />);
} else {
  hydrateRoot(container!, <FullApp />);
}