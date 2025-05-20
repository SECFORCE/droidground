import { $, cd, fs } from "zx";
import { RESOURCES } from "../src/server/config/resources";

$.verbose = true;

const source = `companion/${RESOURCES.COMPANION_FILE}`;
const dest = `resources/${RESOURCES.COMPANION_FILE}`;

cd("companion");
await $`./gradlew assembleRelease`;
cd("..");
await fs.copy(source, dest);
