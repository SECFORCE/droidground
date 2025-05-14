import { createContext, useEffect, useRef, useContext, ReactNode, useCallback, useState } from "react";
import { StreamingPhase, WSCallback, WSMessageType } from "@shared/types";
import toast from "react-hot-toast";

type WebSocketContextType = {
  sendMessage: (message: string) => void;
  subscribe: (topic: WSMessageType, callback: WSCallback) => void;
  unsubscribe: (topic: WSMessageType, callback: WSCallback) => void;
  streamingPhase: StreamingPhase;
};

const WebSocketContext = createContext<WebSocketContextType | undefined>(undefined);

export const WebSocketProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [streamingPhase, setStreamingPhase] = useState<StreamingPhase>(StreamingPhase.INIT);
  const socketRef = useRef<WebSocket | null>(null);
  const listeners = useRef<Map<WSMessageType, Set<WSCallback>>>(new Map());

  useEffect(() => {
    const connect = async () => {
      let webSocketURL = `ws://localhost:4242/streaming`;
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

          const view = new DataView(event.data);
          const metaLen = view.getUint32(0);
          const full = new Uint8Array(event.data);
          const metaBuf = full.slice(4, 4 + metaLen);
          const binaryBuf = full.slice(4 + metaLen);

          const { type, ...metadata } = JSON.parse(new TextDecoder().decode(metaBuf));

          switch (type) {
            case WSMessageType.CONFIGURATION:
              if (streamingPhase !== StreamingPhase.METADATA) {
                setStreamingPhase(StreamingPhase.METADATA);
              }
              break;
            case WSMessageType.DATA:
              if (streamingPhase !== StreamingPhase.RENDER) {
                setStreamingPhase(StreamingPhase.RENDER);
              }
              break;
            case WSMessageType.FRIDA_OUTPUT:
              console.log("Frida output changed");
              break;
          }

          // Notify specific topic listeners
          listeners.current.get(type)?.forEach(callback => callback(metadata, binaryBuf));
        } catch (error) {
          toast.error("WebSocket message parsing error");
          console.error(`WebSocket message parsing error: ${error}`);
        }
      };

      socket.onerror = error => console.error(`WebSocket error: ${error}`);
      socket.onclose = () => console.error("WebSocket Disconnected");
    };

    connect();
  }, []);

  const sendMessage = (message: string) => {
    if (socketRef.current && socketRef.current.readyState === WebSocket.OPEN) {
      socketRef.current.send(message);
    } else {
      console.warn("WebSocket is not open. Message not sent:", message);
    }
  };

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

  return (
    <WebSocketContext.Provider
      value={{
        sendMessage,
        subscribe,
        unsubscribe,
        streamingPhase,
      }}
    >
      {children}
    </WebSocketContext.Provider>
  );
};

export const useWebSocket = () => {
  const context = useContext(WebSocketContext);
  if (!context) {
    throw new Error("useWebSocket must be used within a WebSocketProvider");
  }
  return context;
};
