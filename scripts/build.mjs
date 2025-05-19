$.verbose = true;

import { BIN } from "@yume-chan/fetch-scrcpy-server";

await $`npm run scrcpy`;
await $`npm run companion`;
await $`npm run build:setup`;
await $`npm run build:client`;
await $`npm run build:server`;
await $`npm run copy-files`;

await fs.copy(BIN.pathname, "dist/resources/scrcpy.jar");
await fs.copy("companion/droidground-companion.dex", "dist/resources/droidground-companion.dex");
