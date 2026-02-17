import { LsEntry } from "@server/utils/types";
import { DroidGroundFeatures, FridaLibrary, IntentExtra } from "@shared/types";

/***************************
 *         Generic         *
 **************************/
export interface IGenericResultRes {
  result: string;
}

export interface IGenericErrRes {
  error: string;
}

/***************************
 *           API           *
 **************************/

export interface DroidGroundFeaturesResponse extends DroidGroundFeatures {}

export interface DeviceInfoResponse {
  version: string;
  architecture: string;
  deviceType: string;
  model: string;
}

export interface GetFilesRequest {
  path: string;
}

export interface GetFilesResponse {
  result: LsEntry[];
}

export interface CompanionPackageInfos {
  packageName: string;
  versionName: string;
  apkSize: number;
  label: string;
  icon: string;
  firstInstallTime: number;
  lastUpdateTime: number;
}

export interface BugreportzStatusResponse {
  isRunning: boolean;
  isBugreportAvailable: boolean;
}

export interface StartActivityRequest {
  activity: string; // Fully qualified class, e.g., "com.example/.MainActivity"

  action?: string;
  dataUri?: string;
  mimeType?: string;
  categories?: string[];
  flags?: number;
  extras?: IntentExtra[];
  //user?: number;
}

export interface StartBroadcastRequest {
  receiver: string; // Optional if using action, but making it mandatory makes things easier
  action?: string; // Required if no receiver
  extras?: IntentExtra[];
  //user?: number;
}

export interface StartServiceRequest {
  service: string; // Fully qualified class, e.g., "com.example/.MyService"

  action?: string;
  extras?: IntentExtra[];
  //user?: number;
}

export interface ActionResponse extends IGenericResultRes {
  command: string;
}

export interface FridaLibraryResponse {
  library: FridaLibrary;
}

export interface StartFridaFullScriptRequest {
  code: string;
  language: "js" | "ts";
}

export interface StartFridaLibraryScriptRequest {
  scriptName: string;
  args: Record<string, any>;
}

export interface StartExploitAppRequest {
  packageName: string;
  teamToken?: string;
}

export interface GetAttackSurfaceRequest {
  debugToken: string;
}

export interface TeamTokenGenericRequest {
  teamToken: string;
}

export interface NewTeamResponse {
  teamToken: string;
}
