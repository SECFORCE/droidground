import { $, fs } from "zx";
import { RESOURCES } from "../src/server/config/resources";

$.verbose = true;

const dest = `resources/${RESOURCES.SCRCPY_SERVER}`;

// The CLI downloads the server binary and generates the package's `index.js`
// (which exports `BIN`), so it must run before that module can be imported.
await $`npx fetch-scrcpy-server 3.1`;
const { BIN } = await import("@yume-chan/fetch-scrcpy-server");
await fs.copy(BIN.pathname, dest);
