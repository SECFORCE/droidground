import { DataMetadata, StreamingPhase, WSMessage, WSMessageType, WSMetadata } from "@shared/types";
import { WebsocketClient } from "@server/utils/types";
import { WebSocket } from "ws";

export const sendStructuredMessage = (
  ws: WebSocket,
  type: WSMessageType,
  metadata: WSMetadata,
  binaryData?: Uint8Array,
) => {
  const typedMetadata = {
    ...metadata,
    type,
  };
  const metaBuf = new TextEncoder().encode(JSON.stringify(typedMetadata));
  const metaLenBuf = new Uint8Array(4);
  new DataView(metaLenBuf.buffer).setUint32(0, metaBuf.length);

  const totalLength = 4 + metaBuf.length + (binaryData?.length || 0);
  const fullPayload = new Uint8Array(totalLength);

  fullPayload.set(metaLenBuf, 0);
  fullPayload.set(metaBuf, 4);
  if (binaryData) {
    fullPayload.set(binaryData, 4 + metaBuf.length);
  }

  ws.send(fullPayload);
};

export const broadcastForPhase = (
  websocketClients: Map<string, WebsocketClient>,
  state: StreamingPhase,
  message: WSMessage,
) => {
  for (const [wsClientId, client] of websocketClients) {
    // To avoid issues always send a keyframe first
    if (state === StreamingPhase.RENDER && client.state === StreamingPhase.KEYFRAME) {
      const metadata = message.metadata as DataMetadata;
      if (metadata.keyframe) {
        sendStructuredMessage(client.ws, WSMessageType.DATA, message.metadata, message.data);
        websocketClients.set(wsClientId, { ...client, state: StreamingPhase.RENDER });
      }
    } else if (client.state === state) {
      sendStructuredMessage(client.ws, WSMessageType.DATA, message.metadata, message.data);
    }
  }
};
