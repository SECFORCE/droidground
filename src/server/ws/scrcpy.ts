import { v4 as uuidv4 } from "uuid";
import { WebSocketServer, WebSocket } from "ws";
import { ManagerSingleton } from "@server/manager";
import { StreamingPhase, WSMessageType } from "@shared/types";
import Logger from "@shared/logger";
import { WebsocketClient } from "@server/utils/types";
import { sendStructuredMessage } from "@server/utils/ws";

export const setupScrcpyWss = (wssStreaming: WebSocketServer) => {
  const singleton = ManagerSingleton.getInstance();
  const wsStreamingClients = singleton.wsStreamingClients;

  wssStreaming.on("connection", (ws: WebSocket) => {
    const id = uuidv4();
    wsStreamingClients.set(id, {
      state: StreamingPhase.INIT,
      ws: ws,
    });

    Logger.info(`WebSocket Streaming client connected with id '${id}', sending Metadata message (if available)`);

    if (singleton.sharedVideoMetadata) {
      sendStructuredMessage(ws, WSMessageType.STREAM_METADATA, singleton.sharedVideoMetadata);
    }

    ws.on("message", (clientMessage: any) => {
      const singleton = ManagerSingleton.getInstance();
      let message = clientMessage.toString();
      const currentClientData = wsStreamingClients.get(id) as WebsocketClient;
      switch (message) {
        case WSMessageType.STREAM_METADATA_ACK:
          wsStreamingClients.set(id, { ...(currentClientData as WebsocketClient), state: StreamingPhase.METADATA });
          if (singleton.sharedConfiguration) {
            sendStructuredMessage(ws, WSMessageType.CONFIGURATION, {}, singleton.sharedConfiguration.data);
          }
          break;
        case WSMessageType.CONFIGURATION_ACK:
          const nextState: StreamingPhase =
            singleton.sharedVideoMetadata?.hardwareType === "hardware"
              ? StreamingPhase.KEYFRAME
              : StreamingPhase.RENDER;
          wsStreamingClients.set(id, { ...(currentClientData as WebsocketClient), state: nextState });
          break;
        default:
          Logger.error(`Unknown message type: ${message}`);
          break;
      }
    });

    ws.on("close", () => {
      wsStreamingClients.delete(id);
      Logger.info(`WebSocket client with id '${id}' disconnected`);
    });
  });
};
