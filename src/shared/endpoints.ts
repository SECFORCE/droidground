export const REST_API_ENDPOINTS = {
  FEATURES: "/features",
  INFO: "/info",
  ACTIVITY: "/activity",
  SHUTDOWN: "/shutdown",
  REBOOT: "/reboot",
  LOGCAT: "/logcat",
  FILES: "/files",
  BUGREPORT_STATUS: "/bugreportStatus",
  BUGREPORT: "/bugreport",
  PACKAGES: "/packages",
  APK: "/apk",
} as const;

export const WEBSOCKET_ENDPOINTS = {
  STREAMING: "/streaming",
  TERMINAL: "/terminal",
  FRIDA: "/frida",
} as const;
