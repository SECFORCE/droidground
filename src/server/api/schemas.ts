import { GetFilesRequest, StartActivityRequest, StartBroadcastRequest, StartServiceRequest } from "@shared/api";
import { IntentExtra, IntentExtraType } from "@shared/types";
import { JSONSchemaType } from "ajv";

const intentExtraSchema: JSONSchemaType<IntentExtra> = {
  type: "object",
  properties: {
    key: {
      type: "string",
    },
    type: {
      type: "string",
      enum: Object.keys(IntentExtraType) as readonly IntentExtraType[],
    },
    value: {
      type: ["string", "number", "boolean"],
      nullable: true,
    },
  },
  required: ["key", "type"],
  additionalProperties: false,
};

export const startActivitySchema: JSONSchemaType<StartActivityRequest> = {
  type: "object",
  properties: {
    activity: { type: "string" },
    action: { type: "string", nullable: true },
    dataUri: { type: "string", nullable: true },
    mimeType: { type: "string", nullable: true },
    categories: {
      type: "array",
      nullable: true,
      items: { type: "string" },
    },
    flags: { type: "number", nullable: true },
    extras: {
      type: "array",
      items: intentExtraSchema,
      nullable: true,
    },
  },
  required: ["activity"],
  additionalProperties: false,
};

export const startBroadcastSchema: JSONSchemaType<StartBroadcastRequest> = {
  type: "object",
  properties: {
    receiver: { type: "string" },
    action: { type: "string", nullable: true },
    extras: {
      type: "array",
      items: intentExtraSchema,
      nullable: true,
    },
  },
  required: ["receiver"],
  additionalProperties: false,
};

export const startServiceSchema: JSONSchemaType<StartServiceRequest> = {
  type: "object",
  properties: {
    service: { type: "string" },
    action: { type: "string", nullable: true },
    extras: {
      type: "array",
      items: intentExtraSchema,
      nullable: true,
    },
  },
  required: ["service"],
  additionalProperties: false,
};

export const getFilesSchema: JSONSchemaType<GetFilesRequest> = {
  type: "object",
  properties: {
    path: { type: "string" },
  },
  required: ["path"],
  additionalProperties: false,
};
