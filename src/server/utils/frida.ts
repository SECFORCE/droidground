import { execSync } from "child_process";
import path from "path";
import fs from "fs";
import followRedirects from "follow-redirects";

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
  fs.chmodSync(finalPath, 0o755);

  return finalPath;
};
