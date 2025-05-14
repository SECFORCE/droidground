import { lazy } from "react";

// Normal views
export { Overview } from "@client/views/Overview";
export { Frida } from "@client/views/Frida";
export { FileBrowser } from "@client/views/FileBrowser";
export { AppManager } from "@client/views/AppManager";
export { Logs } from "@client/views/Logs";
export { NotFound } from "@client/views/NotFound";
export { Error } from "@client/views/Error";

// Lazy views
export const Terminal = lazy(() => import("@client/views/Terminal").then(mod => ({ default: mod.Terminal })));
