import frida from 'frida';
import { ScrcpyVideoStreamMetadata } from "@yume-chan/scrcpy"

export interface DroidGroundFeatures {
  startActivityEnabled: boolean;
  startBroadcastReceiverEnabled: boolean;
  startServiceEnabled: boolean;
  shutdownEnabled: boolean;
  rebootEnabled: boolean;
  bugReportEnabled: boolean;
  fridaEnabled: boolean;
  fileBrowserEnabled: boolean;
  appManagerEnabled: boolean;
  terminalEnabled: boolean;
  logcatEnabled: boolean;
}

export interface DroidGroundConfig {
  packageName: string;
  adb: {
    host: string;
    port: number;
  }
  features: DroidGroundFeatures;
}


export enum WSMessageType {
  // Streaming
  STREAM_METADATA = "metadata",
  STREAM_METADATA_ACK = "metadataAck",
  CONFIGURATION = "configuration",
  CONFIGURATION_ACK = "configurationAck",
  DATA = "data",
  // Notifications
  FRIDA_OUTPUT = "frida",
  TERMINAL_OUTPUT = "terminal",
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

// ADB types
export enum IntentExtraType {
  STRING = 'string',
  INT = 'int',
  LONG = 'long',
  FLOAT = 'float',
  BOOL = 'bool',
  URI = 'uri',
  COMPONENT = 'component',
  NULL = 'null'
}
export interface IntentExtra {
  key: string;
  type: IntentExtraType;
  value?: string | number | boolean; // undefined if type is 'null'
}

export interface FridaState {
    device: frida.Device | null;
    pid: frida.ProcessID | null;
    script: frida.Script | null;
}