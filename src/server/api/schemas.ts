import {
  GetFilesRequest,
  StartActivityRequest,
  StartBroadcastRequest,
  StartExploitAppRequest,
  StartServiceRequest,
  TeamTokenGenericRequest,
} from "@shared/api";
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
      enum: Object.values(IntentExtraType) as readonly IntentExtraType[],
    },
    value: {
      anyOf: [
        {
          type: "string",
        },
        {
          type: "number",
        },
        {
          type: "boolean",
        },
      ],
    },
  },
  required: ["key", "type", "value"],
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

export const runExploitAppSchema: JSONSchemaType<StartExploitAppRequest> = {
  type: "object",
  properties: {
    packageName: { type: "string" },
    teamToken: { type: "string", nullable: true },
  },
  required: ["packageName"],
  additionalProperties: false,
};

export const teamTokenGenericReqSchema: JSONSchemaType<TeamTokenGenericRequest> = {
  type: "object",
  properties: {
    teamToken: { type: "string" },
  },
  required: ["teamToken"],
  additionalProperties: false,
};
