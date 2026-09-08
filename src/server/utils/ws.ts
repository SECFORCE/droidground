import { DataMetadata, StreamingPhase, WSMessage, WSMessageType, WSMetadata } from "@shared/types";
import { WebsocketClient } from "@server/utils/types";
import { WebSocket } from "ws";

const textEncoder = new TextEncoder();
export const MAX_VIDEO_BUFFER_BYTES = 256 * 1024;

export const serializeStructuredMessage = (type: WSMessageType, metadata: WSMetadata, binaryData?: Uint8Array) => {
  const typedMetadata = {
    ...metadata,
    type,
  };
  const metaBuf = textEncoder.encode(JSON.stringify(typedMetadata));
  const metaLenBuf = new Uint8Array(4);
  new DataView(metaLenBuf.buffer).setUint32(0, metaBuf.length);

  const totalLength = 4 + metaBuf.length + (binaryData?.length || 0);
  const fullPayload = new Uint8Array(totalLength);

  fullPayload.set(metaLenBuf, 0);
  fullPayload.set(metaBuf, 4);
  if (binaryData) {
    fullPayload.set(binaryData, 4 + metaBuf.length);
  }

  return fullPayload;
};

export const sendStructuredMessage = (
  ws: WebSocket,
  type: WSMessageType,
  metadata: WSMetadata,
  binaryData?: Uint8Array,
) => {
  if (ws.readyState === WebSocket.OPEN) ws.send(serializeStructuredMessage(type, metadata, binaryData));
};

export const broadcastForPhase = (
  websocketClients: Map<string, WebsocketClient>,
  state: StreamingPhase,
  message: WSMessage,
) => {
  let payload: Uint8Array | undefined;
  for (const client of websocketClients.values()) {
    if (client.ws.readyState !== WebSocket.OPEN) continue;
    if (message.type === WSMessageType.CONFIGURATION) {
      if (client.state === StreamingPhase.INIT) continue;
      // Configuration changes (e.g. rotation) also apply to viewers already rendering.
      client.state = StreamingPhase.METADATA;
    } else if (state === StreamingPhase.RENDER) {
      if (client.state !== StreamingPhase.RENDER && client.state !== StreamingPhase.KEYFRAME) continue;
      if (client.ws.bufferedAmount > MAX_VIDEO_BUFFER_BYTES) {
        // Discard a dependent sequence together, then resume at a fresh keyframe.
        client.state = StreamingPhase.KEYFRAME;
        continue;
      }
      if (client.state === StreamingPhase.KEYFRAME && !(message.metadata as DataMetadata).keyframe) continue;
      client.state = StreamingPhase.RENDER;
    } else if (client.state !== state) continue;

    // Package once per frame, even when many teams are watching the same device.
    payload ??= serializeStructuredMessage(message.type, message.metadata, message.data);
    client.ws.send(payload);
  }
};
