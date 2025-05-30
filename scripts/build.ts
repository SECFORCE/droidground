import { $, fs } from "zx";
import { RESOURCES } from "../src/server/config/resources";

$.verbose = true;

const companionSource = `resources/${RESOURCES.COMPANION_FILE}`;
const companionDest = `dist/${companionSource}`;
const scrcpySource = `resources/${RESOURCES.SCRCPY_SERVER}`;
const scrcpynDest = `dist/${scrcpySource}`;
const librarySource = "library";
const libraryDest = "dist/library";

await $`npm run scrcpy`;
await $`npm run companion`;
await $`npm run build:setup`;
await $`npm run build:client`;
await $`npm run build:server`;
await $`npm run copy-files`;

await fs.copy(companionSource, companionDest);
await fs.copy(scrcpySource, scrcpynDest);
await fs.copy(librarySource, libraryDest);
