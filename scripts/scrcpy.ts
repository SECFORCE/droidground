import { $, fs } from "zx";
import { BIN } from "@yume-chan/fetch-scrcpy-server";
import { RESOURCES } from "../src/server/config/resources";

$.verbose = true;

const dest = `resources/${RESOURCES.SCRCPY_SERVER}`;

await $`npx fetch-scrcpy-server 3.1`;
await fs.copy(BIN.pathname, dest);
