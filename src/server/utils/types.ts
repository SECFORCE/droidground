import { StreamingPhase } from "@shared/types";
import { WebSocket } from "ws";

export interface WebsocketClient {
  state: StreamingPhase;
  ws: WebSocket;
}

export type LsEntry = {
  permissions: string;
  links?: number;
  owner?: string;
  group?: string;
  size?: number;
  date?: string;
  name: string;
  linkTarget?: string;
  isSymlink: boolean;
  isCorrupted: boolean;
};
