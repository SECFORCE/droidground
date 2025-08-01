import { execSync } from "child_process";
import path from "path";
import fs from "fs";
import { readFile } from "fs/promises";
import followRedirects from "follow-redirects";
import Ajv from "ajv";
import { ReadableStream } from "@yume-chan/stream-extra";
import { FridaLibrary, FridaScript } from "@shared/types";
import { libraryFile, resourceFile, resourcesDir, safeFileExists } from "@server/utils/helpers";
import Logger from "@shared/logger";
import { DEFAULT_UPLOAD_FOLDER, RESOURCES } from "@server/config";
import { ManagerSingleton } from "@server/manager";

export const getFridaVersion = async () => {
  return execSync("frida --version").toString().trim();
};

export const mapAbiToFridaArch = (abi: string): string => {
  const map: Record<string, string> = {
    "arm64-v8a": "arm64",
    "armeabi-v7a": "arm",
    x86: "x86",
    x86_64: "x86_64",
  };
  return map[abi] || abi;
};

export const downloadFridaServer = async (version: string, arch: string, destFolder: string): Promise<string> => {
  const fileName = `frida-server-${version}-android-${arch}`;
  const xzFileName = `${fileName}.xz`;
  const xzPath = path.join(destFolder, xzFileName);
  const decompressedPath = path.join(destFolder, fileName);
  const finalPath = path.join(destFolder, "frida-server");
  const url = `https://github.com/frida/frida/releases/download/${version}/${xzFileName}`;

  await new Promise((resolve, reject) => {
    const file = fs.createWriteStream(xzPath);
    followRedirects.https
      .get(url, response => {
        if (response.statusCode !== 200) {
          reject(new Error(`Download failed with status ${response.statusCode}`));
          return;
        }
        response.pipe(file);
        file.on("finish", () => {
          file.close(resolve);
        });
      })
      .on("error", reject);
  });

  execSync(`unxz -f ${xzPath}`);

  // Rename to just "frida-server"
  if (fs.existsSync(finalPath)) {
    fs.unlinkSync(finalPath); // Remove existing if needed
  }

  fs.renameSync(decompressedPath, finalPath);

  return finalPath;
};

const fridaScriptSchema = {
  type: "array",
  items: {
    type: "object",
    properties: {
      filename: { type: "string" },
      description: { type: "string" },
    },
    required: ["filename", "description"],
    additionalProperties: false,
  },
};

export const loadFridaLibrary = async (): Promise<FridaLibrary> => {
  const ajv = new Ajv();
  const libraryJsonFile = libraryFile("library.json");
  const data = await readFile(libraryJsonFile, "utf-8");
  const parsed = JSON.parse(data);

  const validate = ajv.compile(fridaScriptSchema);
  const valid = validate(parsed);

  if (!valid) {
    throw new Error("Invalid frida library.json format.");
  }

  const fridaScripts = parsed as FridaScript[];

  const fridaLibrary: FridaLibrary = fridaScripts.map(el => {
    const fridaScript = libraryFile(el.filename);
    const content = fs.readFileSync(fridaScript, "utf-8");
    return {
      ...el,
      content: content,
    };
  });

  return fridaLibrary;
};

export const setupFrida = async () => {
  Logger.info("Downloading Frida Server for the attached device");
  const singleton = ManagerSingleton.getInstance();
  const adb = await singleton.getAdb();
  const fridaVersion = await getFridaVersion();
  const abi = (await adb.subprocess.noneProtocol.spawnWaitText("getprop ro.product.cpu.abi")).trim();
  const arch = mapAbiToFridaArch(abi);

  const fridaServerPath = await downloadFridaServer(fridaVersion, arch, resourcesDir());
  Logger.info(`Frida server downloaded at ${fridaServerPath}`);

  // Push the frida-server
  const sync = await adb.sync();
  const fridaServerDevicePath = path.resolve(DEFAULT_UPLOAD_FOLDER, RESOURCES.FRIDA_SERVER);
  try {
    const fridaFile = resourceFile(RESOURCES.FRIDA_SERVER);
    if (!safeFileExists(fridaFile)) {
      throw new Error("Frida Server file is missing");
    }

    const fridaBuffer: Buffer = await readFile(fridaFile);
    await sync.write({
      filename: fridaServerDevicePath,
      file: new ReadableStream({
        start(controller) {
          controller.enqueue(new Uint8Array(fridaBuffer));
          controller.close();
        },
      }),
      permission: 0o755, // Executable
    });
  } catch (e) {
    Logger.error("Error while pushing Frida Server");
    Logger.error(e);
  } finally {
    await sync.dispose();
  }
  // Start frida-server
  await adb.subprocess.noneProtocol.spawnWaitText("killall frida-server");
  // Just try different formats (it changes based on the version of 'su' available)
  adb.subprocess.noneProtocol.spawn(`su -c '${fridaServerDevicePath}'`);
  adb.subprocess.noneProtocol.spawn(`su root '${fridaServerDevicePath}'`);
  Logger.info("Frida server started");
};
