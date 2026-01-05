/*
Configuration file containing constants
Convention: constants are declared in UPPERCASE
Usage: import { CONSTANT_NAME } from '@/config'
*/

export const PAGES = {
  OVERVIEW: "/",
  FRIDA: "/frida",
  FILE_BROWSER: "/file-browser",
  APP_MANAGER: "/app-manager",
  TERMINAL: "/terminal",
  LOGS: "/logs",
  EXPLOIT_SERVER: "/exploit-server",
  DEBUG: "/debug",
} as const;
