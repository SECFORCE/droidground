import type { ScrcpyEncoder } from "@yume-chan/scrcpy";

export function getScrcpyVideoSettings(env: NodeJS.ProcessEnv = process.env) {
  const number = (name: string, fallback: number, min: number, max: number) => {
    const raw = env[name]?.trim();
    const value = raw ? Number(raw) : NaN;
    return Number.isInteger(value) && value >= min && value <= max ? value : fallback;
  };
  return {
    maxSize: number("DROIDGROUND_SCRCPY_MAX_SIZE", 1280, 0, 8192),
    maxFps: number("DROIDGROUND_SCRCPY_MAX_FPS", 60, 0, 240),
    videoBitRate: number("DROIDGROUND_SCRCPY_VIDEO_BIT_RATE", 4_000_000, 100_000, 100_000_000),
  };
}

export function selectVideoEncoder(encoders: ScrcpyEncoder[]) {
  const h264 = encoders.filter(encoder => encoder.type === "video" && encoder.codec === "h264");
  // Older servers may not report the codec or hardware type.
  const candidates = h264.length ? h264 : encoders.filter(encoder => encoder.type === "video" && !encoder.codec);
  const encoder = candidates.find(encoder => encoder.hardwareType === "hardware") ?? candidates[0];
  if (!encoder) throw new Error("No H.264 video encoder is available on the device");
  return encoder;
}
