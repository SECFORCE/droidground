/*
Configuration file containing constants
Convention: constants are declared in UPPERCASE
Usage: import { CONSTANT_NAME } from '@/config'
*/

export const DEFAULT_UPLOAD_FOLDER = "/data/local/tmp";

export const BUGREPORT_FILENAME = "bugreportz.zip";

export const RESOURCES = {
  COMPANION_FILE: "droidground-companion.dex",
  SCRCPY_SERVER: "scrcpy-server.jar",
  FRIDA_SERVER: "frida-server",
} as const;
