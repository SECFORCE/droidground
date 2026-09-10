import { v4 as uuidv4 } from "uuid";
import { WebSocketServer, WebSocket } from "ws";
import { ManagerSingleton } from "@server/manager";
import { StreamingPhase, WSMessageType } from "@shared/types";
import Logger from "@shared/logger";
import { WebsocketClient } from "@server/utils/types";
import { sendStructuredMessage } from "@server/utils/ws";
import { ScrcpyControlSession } from "@server/utils/scrcpy-control";

export const setupScrcpyWss = (wssStreaming: WebSocketServer) => {
  const singleton = ManagerSingleton.getInstance();
  const wsStreamingClients = singleton.wsStreamingClients;

  wssStreaming.on("connection", (ws: WebSocket) => {
    const id = uuidv4();
    const control = new ScrcpyControlSession(
      () => singleton.getScrcpyController(),
      error => Logger.error({ err: error }, "Scrcpy input failed"),
    );
    wsStreamingClients.set(id, {
      state: StreamingPhase.INIT,
      ws: ws,
    });

    Logger.info(`WebSocket Streaming client connected with id '${id}', sending Metadata message (if available)`);

    if (singleton.sharedVideoMetadata) {
      sendStructuredMessage(ws, WSMessageType.STREAM_METADATA, singleton.sharedVideoMetadata);
    }

    ws.on("message", (clientMessage, isBinary) => {
      if (isBinary) return;
      const singleton = ManagerSingleton.getInstance();
      let message = clientMessage.toString();
      const currentClientData = wsStreamingClients.get(id) as WebsocketClient;
      switch (message) {
        case WSMessageType.STREAM_METADATA_ACK:
          wsStreamingClients.set(id, { ...currentClientData, state: StreamingPhase.KEYFRAME });
          if (singleton.sharedConfiguration) {
            sendStructuredMessage(ws, WSMessageType.CONFIGURATION, {}, singleton.sharedConfiguration.data);
          }
          singleton.requestVideoRefresh();
          break;
        case WSMessageType.CONFIGURATION_ACK: {
          // Configuration precedes frames on the same ordered connection. A late
          // ACK must not put an already playing viewer back into KEYFRAME state.
          break;
        }
        case WSMessageType.STREAM_RESYNC: {
          if (currentClientData.state === StreamingPhase.INIT) break;
          wsStreamingClients.set(id, { ...currentClientData, state: StreamingPhase.KEYFRAME });
          singleton.requestVideoRefresh();
          break;
        }
        default:
          if (singleton.getConfig().features.scrcpyControlEnabled && !control.accept(message)) {
            ws.close(1013, "Too many pending inputs");
            void control.close();
          }
          break;
      }
    });

    ws.on("close", () => {
      void control.close();
      wsStreamingClients.delete(id);
      Logger.info(`WebSocket client with id '${id}' disconnected`);
    });
    ws.on("error", () => {
      void control.close();
    });
  });
};
