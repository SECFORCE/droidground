import { $, fs } from "zx";

$.verbose = true;

await $`npm run build:setup`;
await $`npm run build:client`;
await $`npm run build:spawner`;
await $`npm run copy-files`;
