import { StartFridaLibraryScriptRequest } from "@shared/api";
import { JSONSchemaType } from "ajv";

export const startFridaLibraryScriptSchema: JSONSchemaType<StartFridaLibraryScriptRequest> = {
  type: "object",
  properties: {
    scriptName: {
      type: "string",
    },
    args: {
      type: "object",
      nullable: false,
      additionalProperties: true,
    },
  },
  required: ["scriptName"],
  additionalProperties: false,
};
