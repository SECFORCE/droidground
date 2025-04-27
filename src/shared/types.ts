import { ScrcpyVideoStreamMetadata } from "@yume-chan/scrcpy"

export enum WSMessageType {
  STREAM_METADATA = "metadata",
  STREAM_METADATA_ACK = "metadataAck",
  CONFIGURATION = "configuration",
  CONFIGURATION_ACK = "configurationAck",
  DATA = "data"
}

export enum StreamingPhase {
  INIT = "init", // the client just connected to the websocket, need to send the metadata and wait for the ack
  METADATA = "config", // the client received the metadata and sent back the ack for it, need to send the config packet and wait for the ack
  KEYFRAME = "keyframe", // the client received the config packet and sent back the ack for it, send a packet with a keyframe first
  RENDER = "render" // the client received the config packet and sent back the ack for it, the first keyframe has also been sent. Data packets can be sent
}

export interface StreamMetadata extends ScrcpyVideoStreamMetadata {
  hardwareType: "hardware" | "software" | "hybrid",
  videoEncoder: string
}

export interface ConfigurationMetadata {}

export interface DataMetadata {
  keyframe?: boolean;
  pts: string | null;
}

export type WSMetadata = StreamMetadata | ConfigurationMetadata | DataMetadata 

export interface WSMessage {
  type: WSMessageType,
  metadata: WSMetadata,
  data: Uint8Array
}


export type WSCallback = (metadata: WSMetadata, binaryBuf: Uint8Array<ArrayBuffer>) => void