import { StartFridaFullScriptRequest, StartFridaLibraryScriptRequest } from "@shared/api";
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

export const startFridaFullScriptSchema: JSONSchemaType<StartFridaFullScriptRequest> = {
  type: "object",
  properties: {
    code: {
      type: "string",
    },
    language: {
      type: "string",
      enum: ["js", "ts"],
    },
  },
  required: ["code", "language"],
  additionalProperties: false,
};
