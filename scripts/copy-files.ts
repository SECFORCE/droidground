import { cp, readdir } from "node:fs/promises";
import path from "node:path";

async function copyContents(source: string, destination: string): Promise<void> {
  let entries;

  try {
    entries = await readdir(source, { withFileTypes: true });
  } catch (error) {
    if (typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT") {
      return;
    }

    throw error;
  }

  for (const entry of entries) {
    if (entry.name.startsWith(".")) {
      continue;
    }

    await cp(path.join(source, entry.name), path.join(destination, entry.name), {
      recursive: true,
      force: true,
    });
  }
}

await copyContents("public", "dist/public");
await copyContents("dist/client", "dist");
await copyContents("dist/client/assets", "dist/public/assets");
