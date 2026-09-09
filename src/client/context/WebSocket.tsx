import { createContext, useEffect, useRef, useContext, ReactNode, useCallback, useState, useMemo } from "react";
import { StreamingPhase, WSCallback, WSMessageType } from "@shared/types";
import toast from "react-hot-toast";
import { WEBSOCKET_ENDPOINTS } from "@shared/endpoints";
import { useAPI } from "@client/context/API";
import { parseVideoMessage } from "@client/utils/video-stream";

type WebSocketContextType = {
  sendMessage: (message: string) => void;
  subscribe: (topic: WSMessageType, callback: WSCallback) => void;
  unsubscribe: (topic: WSMessageType, callback: WSCallback) => void;
  streamingPhase: StreamingPhase;
};

const WebSocketContext = createContext<WebSocketContextType | undefined>(undefined);

export const WebSocketProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const { featuresConfig } = useAPI();
  const [streamingPhase, setStreamingPhase] = useState<StreamingPhase>(StreamingPhase.INIT);
  const phaseRef = useRef(StreamingPhase.INIT);
  const socketRef = useRef<WebSocket | null>(null);
  const listeners = useRef<Map<WSMessageType, Set<WSCallback>>>(new Map());
  const updatePhase = useCallback((phase: StreamingPhase) => {
    if (phaseRef.current === phase) return;
    phaseRef.current = phase;
    setStreamingPhase(phase);
  }, []);

  useEffect(() => {
    const connect = async () => {
      const isHttps = typeof window !== "undefined" && window.location.protocol === "https:";
      const prefix = isHttps ? "wss" : "ws";
      const suffix = featuresConfig.basePath.length > 0 ? featuresConfig.basePath : "";
      const wsBaseUrl = `${prefix}://${window.location.host}${suffix}`;
      let webSocketURL = `${wsBaseUrl}${WEBSOCKET_ENDPOINTS.STREAMING}`;
      const socket = new WebSocket(webSocketURL);
      socket.binaryType = "arraybuffer";
      socketRef.current = socket;

      socket.onopen = () => console.log("WebSocket Connected");
      socket.onmessage = event => {
        try {
          if (!(event.data instanceof ArrayBuffer)) {
            console.warn("Received non-binary data:", event.data);
            return;
          }

          const { type, metadata, data } = parseVideoMessage(event.data);

          switch (type) {
            case WSMessageType.CONFIGURATION:
              updatePhase(StreamingPhase.METADATA);
              break;
            case WSMessageType.DATA:
              updatePhase(StreamingPhase.RENDER);
              break;
          }

          // Notify specific topic listeners
          listeners.current.get(type)?.forEach(callback => callback(metadata, data));
        } catch (error) {
          toast.error("WebSocket message parsing error");
          console.error(`WebSocket message parsing error: ${error}`);
        }
      };

      socket.onerror = error => console.error(`WebSocket error: ${error}`);
      socket.onclose = () => {
        updatePhase(StreamingPhase.INIT);
        console.error("WebSocket Disconnected");
      };
    };

    connect();
    return () => {
      socketRef.current?.close();
      socketRef.current = null;
    };
  }, [featuresConfig.basePath, updatePhase]);

  const sendMessage = useCallback((message: string) => {
    if (socketRef.current && socketRef.current.readyState === WebSocket.OPEN) {
      socketRef.current.send(message);
    } else {
      console.warn("WebSocket is not open. Message not sent.");
    }
  }, []);

  const subscribe = useCallback((topic: WSMessageType, callback: WSCallback) => {
    if (!listeners.current.has(topic)) {
      listeners.current.set(topic, new Set());
    }
    listeners.current.get(topic)?.add(callback);
  }, []);

  const unsubscribe = useCallback((topic: WSMessageType, callback: WSCallback) => {
    listeners.current.get(topic)?.delete(callback);
    if (listeners.current.get(topic)?.size === 0) {
      listeners.current.delete(topic);
    }
  }, []);

  const value = useMemo(
    () => ({ sendMessage, subscribe, unsubscribe, streamingPhase }),
    [sendMessage, subscribe, unsubscribe, streamingPhase],
  );
  return <WebSocketContext.Provider value={value}>{children}</WebSocketContext.Provider>;
};

export const useWebSocket = () => {
  const context = useContext(WebSocketContext);
  if (!context) {
    throw new Error("useWebSocket must be used within a WebSocketProvider");
  }
  return context;
};
