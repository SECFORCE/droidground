$.verbose = true;

import { BIN } from "@yume-chan/fetch-scrcpy-server";

await $`npx fetch-scrcpy-server 3.1`;
await fs.copy(BIN.pathname, "resources/scrcpy-server.jar");
