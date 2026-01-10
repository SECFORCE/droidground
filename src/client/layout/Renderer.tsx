import { DataMetadata, StreamingPhase, WSCallback, WSMessageType } from "@shared/types";
import { ScrcpyVideoCodecId, ScrcpyVideoStreamMetadata } from "@yume-chan/scrcpy";
import type { ScrcpyMediaStreamPacket } from "@yume-chan/scrcpy";
import type { VideoFrameRenderer } from "@yume-chan/scrcpy-decoder-webcodecs";
import { TinyH264Decoder } from "@yume-chan/scrcpy-decoder-tinyh264";
import {
  WebGLVideoFrameRenderer,
  BitmapVideoFrameRenderer,
  WebCodecsVideoDecoder,
} from "@yume-chan/scrcpy-decoder-webcodecs";
import { useEffect, useRef, useState } from "react";
import Lottie from "lottie-react";
import bootData from "@client/assets/boot.json";
import { useWebSocket } from "@client/context/WebSocket";
import toast from "react-hot-toast";

interface EnhancedStreamMetadata extends ScrcpyVideoStreamMetadata {
  hardwareType: "hardware" | "software" | "hybrid";
  encoder: string;
}

enum Renderer {
  TinyH264,
  WebCodecs,
}

const TinyH264Renderer: React.FC = () => {
  const { sendMessage, subscribe, unsubscribe, streamingPhase } = useWebSocket();
  // Store latest state in a ref to avoid stale closures
  const controllerRef = useRef<ReadableStreamDefaultController<ScrcpyMediaStreamPacket> | null>(null);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const configListener: WSCallback = async (_metadata, binaryData) => {
      if (!binaryData) return;
      controllerRef.current?.enqueue({ type: "configuration", data: binaryData });
      sendMessage(WSMessageType.CONFIGURATION_ACK);
    };

    const dataListener: WSCallback = async (m, binaryData) => {
      const metadata = m as DataMetadata;
      if (!binaryData) return;
      controllerRef.current?.enqueue({
        type: "data",
        keyframe: metadata.keyframe,
        pts: metadata.pts ? BigInt(metadata.pts) : undefined,
        data: binaryData,
      });
    };

    const start = () => {
      try {
        const stream = new ReadableStream<ScrcpyMediaStreamPacket>({
          start(controller) {
            controllerRef.current = controller;
          },
        });

        subscribe(WSMessageType.CONFIGURATION, configListener);
        subscribe(WSMessageType.DATA, dataListener);

        const decoder = new TinyH264Decoder({ canvas: canvasRef.current as HTMLCanvasElement });
        void stream.pipeTo(decoder.writable);
        sendMessage(WSMessageType.STREAM_METADATA_ACK);
      } catch (err) {
        console.error(err);
        toast.error("Error while starting rendering");
      }
    };

    if (canvasRef.current) {
      start();
    }

    return () => {
      unsubscribe(WSMessageType.CONFIGURATION, configListener);
      unsubscribe(WSMessageType.DATA, dataListener);
    };
  }, [canvasRef]);

  return (
    <div className={streamingPhase !== StreamingPhase.RENDER ? "hidden" : "block"}>
      <canvas ref={canvasRef} />
    </div>
  );
};

const WebCodecsRenderer: React.FC = () => {
  const { sendMessage, subscribe, unsubscribe, streamingPhase } = useWebSocket();
  const containerRef = useRef<HTMLDivElement>(null);
  const controllerRef = useRef<ReadableStreamDefaultController<ScrcpyMediaStreamPacket> | null>(null);

  const createVideoFrameRenderer = (): {
    renderer: VideoFrameRenderer;
    element: HTMLVideoElement | HTMLCanvasElement;
  } => {
    // Uncomment following lines to enable InsertableStreamVideoFrameRenderer, see quirks above
    // if (InsertableStreamVideoFrameRenderer.isSupported) {
    //   const renderer = new InsertableStreamVideoFrameRenderer();
    //   return { renderer, element: renderer.element };
    // }

    if (WebGLVideoFrameRenderer.isSupported) {
      const renderer = new WebGLVideoFrameRenderer();
      return { renderer, element: renderer.canvas as HTMLCanvasElement };
    }

    const renderer = new BitmapVideoFrameRenderer();
    return { renderer, element: renderer.canvas as HTMLCanvasElement };
  };

  useEffect(() => {
    const configListener: WSCallback = async (_metadata, binaryData) => {
      if (!binaryData) return;
      controllerRef.current?.enqueue({ type: "configuration", data: binaryData });
      sendMessage(WSMessageType.CONFIGURATION_ACK);
    };

    const dataListener: WSCallback = async (m, binaryData) => {
      const metadata = m as DataMetadata;
      if (!binaryData) return;
      controllerRef.current?.enqueue({
        type: "data",
        keyframe: metadata.keyframe,
        pts: metadata.pts ? BigInt(metadata.pts) : undefined,
        data: binaryData,
      });
    };

    const start = () => {
      try {
        const stream = new ReadableStream<ScrcpyMediaStreamPacket>({
          start(controller) {
            controllerRef.current = controller;
          },
        });

        subscribe(WSMessageType.CONFIGURATION, configListener);
        subscribe(WSMessageType.DATA, dataListener);

        const { renderer, element } = createVideoFrameRenderer();
        (containerRef.current as HTMLDivElement).appendChild(element);
        const decoder = new WebCodecsVideoDecoder({
          codec: ScrcpyVideoCodecId.H264,
          renderer: renderer as VideoFrameRenderer,
        });
        void stream.pipeTo(decoder.writable);
        sendMessage(WSMessageType.STREAM_METADATA_ACK);
      } catch (err) {
        console.error(err);
        toast.error("Error while starting rendering");
      }
    };

    if (containerRef.current) {
      start();
    }

    return () => {
      unsubscribe(WSMessageType.CONFIGURATION, configListener);
      unsubscribe(WSMessageType.DATA, dataListener);
    };
  }, [containerRef]);

  return <div className={streamingPhase !== StreamingPhase.RENDER ? "hidden" : "block"} ref={containerRef} />;
};

export const VideoRenderer: React.FC = () => {
  const [rendererType, setRendererType] = useState<Renderer | null>();
  const { subscribe, unsubscribe, streamingPhase } = useWebSocket();

  useEffect(() => {
    const metadataListener: WSCallback = m => {
      const metadata = m as EnhancedStreamMetadata;
      setRendererType(metadata.hardwareType === "hardware" ? Renderer.WebCodecs : Renderer.TinyH264);
    };
    subscribe(WSMessageType.STREAM_METADATA, metadataListener);

    return () => {
      unsubscribe(WSMessageType.STREAM_METADATA, metadataListener);
    };
  }, [subscribe, unsubscribe]);

  return (
    <div
      className={`m-auto w-3/4 min-w-3/4 sm:w-1/2 sm:min-w-1/2 lg:w-1/4 lg:min-w-1/4 rounded-2xl border-10 border-black shadow-2xl flex items-center justify-center relative overflow-hidden ${streamingPhase !== StreamingPhase.RENDER ? "aspect-9/16 bg-gray-950" : "bg-transparent "}`}
    >
      {/* Speaker + Camera Dot */}
      <div className="absolute top-2 w-full flex justify-center items-center z-10">
        <div className="w-20 h-2 bg-black rounded-full"></div>
        <div className="w-2 h-2 bg-black rounded-full ml-2"></div>
      </div>
      {streamingPhase !== StreamingPhase.RENDER && (
        <div className="w-10/12">
          <Lottie animationData={bootData} loop={true} />
        </div>
      )}
      {rendererType === Renderer.TinyH264 && <TinyH264Renderer />}
      {rendererType === Renderer.WebCodecs && <WebCodecsRenderer />}
    </div>
  );
};
