import { JSONSchemaType } from "ajv";
import { ScriptExports } from "frida";
import { WebSocket } from "ws";
import { StreamingPhase } from "@shared/types";

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

export type CompanionAttackSurface = {
  activities: string[];
  services: string[];
  receivers: string[];
  providers: string[];
};

export type CompanionAttackSurfaceResponse = {
  attackSurfaces: {
    [packageName: string]: CompanionAttackSurface;
  };
};

export interface IFridaRPC extends ScriptExports {
  run: (args: any) => Promise<void>;
  schema: () => Promise<null | JSONSchemaType<any>>;
}
