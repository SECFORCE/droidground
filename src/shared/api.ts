import { IntentExtra } from "@shared/types";

/***************************
 *         Generic         *
 **************************/
export interface IGenericMsgRes {
  result: string;
}

export interface IGenericErrRes {
  error: string;
}

/***************************
 *           API           *
 **************************/

export interface RunFridaScriptRequest {
    script: string
}

export interface StartActivityRequest {
    activity: string; // Fully qualified class, e.g., "com.example/.MainActivity"
  
    action?: string;
    dataUri?: string;
    mimeType?: string;
    categories?: string[];
    flags?: number;
    extras?: IntentExtra[];
    user?: number;
}
  
export interface StartBroadcastRequest {
    receiver?: string; // Optional if using action
    action?: string;   // Required if no receiver
    extras?: IntentExtra[];
    user?: number;
}

export interface StartServiceRequest {
    service: string; // Fully qualified class, e.g., "com.example/.MyService"

    action?: string;
    extras?: IntentExtra[];
    user?: number;
}