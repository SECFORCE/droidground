// Package imports
import * as fs from "fs";
import { LsEntry } from "@server/utils/types";

export const safeFileExists = (filePath: string) => {
  try {
    fs.accessSync(filePath, fs.constants.F_OK);
    return true;
  } catch (error) {
    return false;
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
