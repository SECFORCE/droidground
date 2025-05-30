export const REST_API_ENDPOINTS = {
  RESET: "/reset", // run the reset.sh script
  FEATURES: "/features",
  INFO: "/info",
  RESTART: "/restart", // restart the target app
  ACTIVITY: "/activity",
  BROADCAST: "/broadcast",
  SERVICE: "/service",
  SHUTDOWN: "/shutdown",
  REBOOT: "/reboot",
  LOGCAT: "/logcat",
  FILES: "/files",
  BUGREPORT_STATUS: "/bugreportStatus",
  BUGREPORT: "/bugreport",
  PACKAGES: "/packages",
  APK: "/apk",
  LIBRARY: "/library",
  EXPLOIT_APP: "/exploitApp",
} as const;

export const WEBSOCKET_ENDPOINTS = {
  STREAMING: "/streaming",
  TERMINAL: "/terminal",
  FRIDA: "/frida",
} as const;
