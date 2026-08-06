import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { RESOURCES } from "../src/server/config/resources";

const version = "3.1";
const expectedSha256 = "958f0944a62f23b1f33a16e9eb14844c1a04b882ca175a738c16d23cb22b86c0";
const dest = `resources/${RESOURCES.SCRCPY_SERVER}`;
const url = `https://github.com/Genymobile/scrcpy/releases/download/v${version}/scrcpy-server-v${version}`;

console.log(`Downloading scrcpy server v${version}...`);
const response = await fetch(url);
if (!response.ok) {
  throw new Error(`Failed to download scrcpy server: ${response.status} ${response.statusText}`);
}

const server = Buffer.from(await response.arrayBuffer());
const sha256 = createHash("sha256").update(server).digest("hex");
if (sha256 !== expectedSha256) {
  throw new Error(`Invalid scrcpy server checksum: expected ${expectedSha256}, received ${sha256}`);
}

await mkdir(dirname(dest), { recursive: true });
await writeFile(dest, server);
console.log(`Saved verified scrcpy server to ${dest}`);
