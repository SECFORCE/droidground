import { DataMetadata, StreamingPhase, WSCallback, WSMessageType } from "@shared/types";
import { ScrcpyVideoCodecId } from "@yume-chan/scrcpy";
import { TinyH264Decoder } from "@yume-chan/scrcpy-decoder-tinyh264";
import {
  WebGLVideoFrameRenderer,
  BitmapVideoFrameRenderer,
  WebCodecsVideoDecoder,
} from "@yume-chan/scrcpy-decoder-webcodecs";
import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { AnimatePresence, motion, useReducedMotion } from "motion/react";
import { LuLockKeyhole } from "react-icons/lu";
import Lottie from "lottie-react";
import bootData from "@client/assets/boot.json";
import { useWebSocket } from "@client/context/WebSocket";
import toast from "react-hot-toast";
import { useAPI } from "@client/context/API";
import { bindScrcpyControls } from "@client/utils/scrcpy-control";
import { LiveVideoDecoder } from "@client/utils/video-stream";

const DeviceVideoRenderer: React.FC = () => {
  const { sendMessage, subscribe, unsubscribe, streamingPhase } = useWebSocket();
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    // Android's encoder and the browser's decoder are independent capabilities.
    let useWebCodecs = WebCodecsVideoDecoder.isSupported;
    let stopped = false;
    const live = new LiveVideoDecoder(
      () => {
        const canvas = document.createElement("canvas");
        const previousCanvas = container.querySelector("canvas");
        if (previousCanvas) {
          canvas.width = previousCanvas.width;
          canvas.height = previousCanvas.height;
        }
        const decoder = useWebCodecs
          ? new WebCodecsVideoDecoder({
              codec: ScrcpyVideoCodecId.H264,
              renderer: WebGLVideoFrameRenderer.isSupported
                ? new WebGLVideoFrameRenderer(canvas)
                : new BitmapVideoFrameRenderer(canvas),
            })
          : new TinyH264Decoder({ canvas });
        container.replaceChildren(canvas);
        return decoder;
      },
      error => {
        if (stopped) return;
        console.error("Video decoder error", error);
        if (useWebCodecs) {
          useWebCodecs = false;
          console.info("Falling back to the software video decoder");
        } else {
          toast.error("Error decoding the device screen", { id: "video-decoder-error" });
        }
      },
    );

    const configListener: WSCallback = (_metadata, data) => {
      if (!data.length) return;
      live.configure(data);
      sendMessage(WSMessageType.CONFIGURATION_ACK);
    };
    const dataListener: WSCallback = (m, data) => {
      if (!data.length) return;
      const metadata = m as DataMetadata;
      live.push(
        {
          type: "data",
          keyframe: metadata.keyframe,
          pts: metadata.pts !== null ? BigInt(metadata.pts) : undefined,
          data,
        },
        !document.hidden,
      );
    };
    subscribe(WSMessageType.CONFIGURATION, configListener);
    subscribe(WSMessageType.DATA, dataListener);
    sendMessage(WSMessageType.STREAM_METADATA_ACK);

    return () => {
      stopped = true;
      unsubscribe(WSMessageType.CONFIGURATION, configListener);
      unsubscribe(WSMessageType.DATA, dataListener);
      live.dispose();
      container.replaceChildren();
    };
  }, [sendMessage, subscribe, unsubscribe]);

  return <div className={streamingPhase !== StreamingPhase.RENDER ? "hidden" : "block"} ref={containerRef} />;
};

export const VideoRenderer: React.FC = () => {
  const [streamReady, setStreamReady] = useState(false);
  const { subscribe, unsubscribe, streamingPhase, sendMessage } = useWebSocket();
  const { featuresConfig } = useAPI();
  const screenRef = useRef<HTMLDivElement>(null);
  const [disabledNotice, setDisabledNotice] = useState<{ x: number; y: number } | null>(null);
  const reduceMotion = useReducedMotion();
  const controlEnabled = featuresConfig.scrcpyControlEnabled && streamingPhase === StreamingPhase.RENDER;

  useEffect(() => {
    if (streamingPhase === StreamingPhase.INIT) setStreamReady(false);
  }, [streamingPhase]);

  useEffect(() => {
    if (!disabledNotice) return;
    const timeout = window.setTimeout(() => setDisabledNotice(null), 2000);
    return () => window.clearTimeout(timeout);
  }, [disabledNotice]);

  useEffect(() => {
    if (!controlEnabled || !screenRef.current) return;
    return bindScrcpyControls(screenRef.current, message => sendMessage(JSON.stringify(message)));
  }, [controlEnabled, sendMessage]);

  useEffect(() => {
    const metadataListener: WSCallback = () => setStreamReady(true);
    subscribe(WSMessageType.STREAM_METADATA, metadataListener);

    return () => {
      unsubscribe(WSMessageType.STREAM_METADATA, metadataListener);
    };
  }, [subscribe, unsubscribe]);

  return (
    <div
      ref={screenRef}
      onClick={event => {
        if (featuresConfig.scrcpyControlEnabled) return;
        const halfWidth = Math.min(112, (window.innerWidth - 24) / 2);
        setDisabledNotice({
          x: Math.max(halfWidth + 12, Math.min(window.innerWidth - halfWidth - 12, event.clientX)),
          y: Math.max(80, event.clientY - 14),
        });
      }}
      tabIndex={controlEnabled ? 0 : undefined}
      role={controlEnabled ? "application" : undefined}
      aria-label={
        controlEnabled
          ? "Device screen. Click or tap to control, then type. Escape goes back. Tab leaves the screen."
          : "Device screen"
      }
      title={
        controlEnabled
          ? "Click or tap to control · Type when focused · Escape or right-click: Back · Tab: leave screen"
          : undefined
      }
      style={controlEnabled ? { touchAction: "none", userSelect: "none" } : undefined}
      className={`mx-auto w-3/4 min-w-3/4 sm:w-1/2 sm:min-w-1/2 lg:w-1/4 lg:min-w-1/4 rounded-2xl border-10 border-black shadow-2xl flex items-center justify-center relative overflow-hidden ${controlEnabled ? "cursor-pointer focus-visible:outline-2 focus-visible:outline-primary focus-visible:outline-offset-4" : ""} ${streamingPhase !== StreamingPhase.RENDER ? "aspect-9/16 bg-gray-950" : "bg-transparent "}`}
    >
      {/* Speaker + Camera Dot */}
      <div className="absolute top-2 w-full flex justify-center items-center z-10 pointer-events-none">
        <div className="w-20 h-2 bg-black rounded-full"></div>
        <div className="w-2 h-2 bg-black rounded-full ml-2"></div>
      </div>
      {streamingPhase !== StreamingPhase.RENDER && (
        <div className="w-10/12">
          <Lottie animationData={bootData} loop={true} />
        </div>
      )}
      {streamReady && <DeviceVideoRenderer />}
      {typeof document !== "undefined" &&
        createPortal(
          <AnimatePresence>
            {disabledNotice && !featuresConfig.scrcpyControlEnabled && (
              <div
                className="pointer-events-none fixed z-50 w-56 max-w-[calc(100vw-24px)] -translate-x-1/2 -translate-y-full"
                style={{ left: disabledNotice.x, top: disabledNotice.y }}
              >
                <motion.div
                  role="status"
                  initial={{ opacity: 0, y: reduceMotion ? 0 : 6, scale: reduceMotion ? 1 : 0.96 }}
                  animate={{ opacity: 1, y: 0, scale: 1 }}
                  exit={{ opacity: 0, y: reduceMotion ? 0 : -4 }}
                  transition={{ duration: 0.18 }}
                  className="relative flex items-center gap-3 rounded-xl border border-white/15 bg-gray-950/95 px-4 py-3 text-white shadow-xl shadow-black/30 backdrop-blur-md"
                >
                  <LuLockKeyhole className="size-5 shrink-0 text-amber-300" aria-hidden="true" />
                  <div>
                    <p className="text-sm font-medium">View-only mode</p>
                    <p className="text-xs text-gray-400">Device control is disabled.</p>
                  </div>
                  <span className="absolute -bottom-1 left-1/2 size-2 -translate-x-1/2 rotate-45 border-r border-b border-white/15 bg-gray-950" />
                </motion.div>
              </div>
            )}
          </AnimatePresence>,
          document.body,
        )}
    </div>
  );
};
