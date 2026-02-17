// Package imports
import * as fs from "node:fs";
import { NetworkInterfaceInfo, networkInterfaces } from "os";
import { LsEntry } from "@server/utils/types";
import { fileURLToPath } from "url";
import path, { dirname } from "path";
import { IntentExtra, IntentExtraType } from "@shared/types";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export const rootDir = () => {
  return path.resolve(__dirname, "..", "..", "..");
};

export const resourcesDir = () => {
  return path.resolve(rootDir(), "resources");
};

export const fridaScriptsDir = () => {
  return path.resolve(rootDir(), "library");
};

export const resourceFile = (filename: string) => {
  return path.resolve(resourcesDir(), filename);
};

export const libraryFile = (filename: string) => {
  return path.resolve(fridaScriptsDir(), filename);
};

export const safeFileExists = (filePath: string) => {
  try {
    fs.accessSync(filePath, fs.constants.F_OK);
    return true;
  } catch (error) {
    return false;
  }
};

export const ensureFolderExists = (dirPath: string) => {
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
  }
};

const codenamesMap: { [versionNumber: string]: string } = {
  "1.0": "Apple Pie",
  "1.1": "Banana Bread",
  "1.5": "Cupcake",
  "1.6": "Donut",
  "2.0": "Eclair",
  "2.0.1": "Eclair",
  "2.1": "Eclair",
  "2.2": "Froyo",
  "2.2.3": "Froyo",
  "2.3": "Gingerbread",
  "2.3.7": "Gingerbread",
  "3.0": "Honeycomb",
  "3.2.6": "Honeycomb",
  "4.0": "Ice Cream Sandwich",
  "4.0.4": "Ice Cream Sandwich",
  "4.1": "Jelly Bean",
  "4.2": "Jelly Bean",
  "4.3": "Jelly Bean",
  "4.4": "KitKat",
  "5.0": "Lollipop",
  "5.1": "Lollipop",
  "6.0": "Marshmallow",
  "7.0": "Nougat",
  "7.1": "Nougat",
  "8.0": "Oreo",
  "8.1": "Oreo",
  "9": "Pie",
  "10": "Quince Tart",
  "11": "Red Velvet Cake",
  "12": "Snow Cone",
  "12L": "Snow Cone v2",
  "13": "Tiramisu",
  "14": "Upside Down Cake",
  "15": "Vanilla Ice Cream",
  "16": "Baklava",
};

export const versionNumberToCodename = (versionNumber: string): string => {
  // Try exact match
  if (codenamesMap[versionNumber]) return codenamesMap[versionNumber];

  // Try major version fallback (e.g., "4.2.2" -> "4.2")
  const majorMinor = versionNumber.split(".").slice(0, 2).join(".");
  if (codenamesMap[majorMinor]) return codenamesMap[majorMinor];

  const majorOnly = versionNumber.split(".")[0];
  if (codenamesMap[majorOnly]) return codenamesMap[majorOnly];

  return "Unknown";
};

export const parseLsAlOutput = (output: string): LsEntry[] => {
  const lines = output.trim().split("\n");
  const entries: LsEntry[] = [];

  for (const line of lines) {
    if (line.startsWith("total")) continue;

    // Match valid entries (with or without symlink)
    const regex =
      /^([\-ldcbspxrwtT\?]{10})\s+(\d+|\?)\s+(\S+|\?)\s+(\S+|\?)\s+(\d+|\?)\s+(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2})\s+(.+?)(?: -> (.+))?$/;

    const match = line.match(regex);
    if (match) {
      const [, permissions, links, owner, group, size, datePart, timePart, name, linkTarget] = match;

      entries.push({
        permissions,
        links: links === "?" ? undefined : parseInt(links, 10),
        owner: owner === "?" ? undefined : owner,
        group: group === "?" ? undefined : group,
        size: size === "?" ? undefined : parseInt(size, 10),
        date: `${datePart} ${timePart}`,
        name,
        linkTarget,
        isSymlink: permissions.startsWith("l"),
        isCorrupted: permissions.includes("?"),
      });
    } else {
      // Fallback if the line doesn't match expected pattern
      entries.push({
        permissions: "",
        name: line.trim(),
        isSymlink: false,
        isCorrupted: true,
      });
    }
  }

  return entries;
};

export const buildExtra = (extra: IntentExtra): string[] => {
  const { key, type, value } = extra;

  switch (type) {
    case IntentExtraType.STRING:
      return [`--es ${shellEscape(key)} ${shellEscape(String(value))}`];
    case IntentExtraType.INT:
      return [`--ei ${shellEscape(key)} ${parseInt(String(value), 10)}`];
    case IntentExtraType.LONG:
      return [`--el ${shellEscape(key)} ${parseInt(String(value), 10)}`];
    case IntentExtraType.FLOAT:
      return [`--ef ${shellEscape(key)} ${parseFloat(String(value))}`];
    case IntentExtraType.BOOL:
      return [`--ez ${shellEscape(key)} ${String(value) === "true"}`];
    case IntentExtraType.URI:
      return [`--eu ${shellEscape(key)} ${shellEscape(String(value))}`];
    case IntentExtraType.COMPONENT:
      return [`--ecn ${shellEscape(key)} ${shellEscape(String(value))}`];
    case IntentExtraType.NULL:
      return [`--esn ${shellEscape(key)}`];
    default:
      throw new Error(`Unsupported extra type: ${type}`);
  }
};

export const shellEscape = (value: string): string => {
  return `'${value.replace(/'/g, `'\\''`)}'`;
};

export const getIP = (name: string) => {
  // Return an empty string by default
  let ipAddress = "";

  const interfaces = networkInterfaces();
  const ifaceKeys = Object.keys(interfaces);

  // Check if there is at least one interface that starts with "name" (fallback check)
  if (!ifaceKeys.some(i => i.startsWith(name))) {
    return ipAddress;
  }

  let iface;
  if (ifaceKeys.includes(name)) {
    // Exact match
    iface = (interfaces[name] as NetworkInterfaceInfo[]).find(i => i.family === "IPv4");
  } else {
    // Fallback
    const firstMatch = ifaceKeys.find(i => i.startsWith(name)) as string;
    iface = (interfaces[firstMatch] as NetworkInterfaceInfo[]).find(i => i.family === "IPv4");
  }

  if (!iface || iface.internal) {
    return ipAddress;
  }

  return iface.address;
};

export const parseValidUrl = (input: string): string | null => {
  if (typeof input !== "string") return null;

  const trimmed = input.trim();

  // Only allow printable ASCII (0x20–0x7E) — rejects control chars, null bytes, and non-ASCII
  if (!/^[\x20-\x7e]+$/.test(trimmed)) return null;

  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    return null;
  }

  // Scheme: only http or https
  if (url.protocol !== "http:" && url.protocol !== "https:") return null;

  // Hostname: must be non-empty and consist of valid domain characters only
  if (!/^[a-zA-Z0-9.-]+$/.test(url.hostname)) return null;

  // No credentials allowed (rejects open-redirect via @)
  if (url.username || url.password) return null;

  // Path, search, hash: only allow safe characters after deep-decoding
  // This also defeats multi-encoded traversal (e.g. %252e%252e)
  const deepDecode = (s: string): string => {
    for (let i = 0, prev = ""; i < 10 && s !== prev; i++) {
      prev = s;
      try {
        s = decodeURIComponent(s);
      } catch {
        break;
      }
    }
    return s;
  };

  const safePath = /^[a-zA-Z0-9/._~!$&'()*+,;:@=-]*$/;
  const parts = [url.pathname, url.search, url.hash];

  for (const part of parts) {
    const decoded = deepDecode(part);
    // Reject if decoded value contains disallowed characters
    if (!safePath.test(decoded)) return null;
    // Reject path traversal
    if (decoded.split("/").includes("..")) return null;
  }

  return url.toString();
};
