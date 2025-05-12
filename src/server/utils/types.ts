import { StreamingPhase } from "@shared/types"
import { WebSocket } from 'ws';

export interface WebsocketClient {
  state: StreamingPhase
  ws: WebSocket
}