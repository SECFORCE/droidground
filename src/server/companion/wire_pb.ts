// @generated by protoc-gen-es v2.4.0 with parameter "target=ts"
// @generated from file wire.proto (package com.secforce.droidground, syntax proto3)
/* eslint-disable */

import type { GenFile, GenMessage } from "@bufbuild/protobuf/codegenv1";
import { fileDesc, messageDesc } from "@bufbuild/protobuf/codegenv1";
import type { Message } from "@bufbuild/protobuf";

/**
 * Describes the file wire.proto.
 */
export const file_wire: GenFile = /*@__PURE__*/
  fileDesc("Cgp3aXJlLnByb3RvEhhjb20uc2VjZm9yY2UuZHJvaWRncm91bmQiNQoHUmVxdWVzdBIKCgJpZBgBIAEoCRIOCgZtZXRob2QYAiABKAkSDgoGcGFyYW1zGAMgASgJIiYKCFJlc3BvbnNlEgoKAmlkGAEgASgJEg4KBnJlc3VsdBgCIAEoCWIGcHJvdG8z");

/**
 * @generated from message com.secforce.droidground.Request
 */
export type Request = Message<"com.secforce.droidground.Request"> & {
  /**
   * @generated from field: string id = 1;
   */
  id: string;

  /**
   * @generated from field: string method = 2;
   */
  method: string;

  /**
   * @generated from field: string params = 3;
   */
  params: string;
};

/**
 * Describes the message com.secforce.droidground.Request.
 * Use `create(RequestSchema)` to create a new message.
 */
export const RequestSchema: GenMessage<Request> = /*@__PURE__*/
  messageDesc(file_wire, 0);

/**
 * @generated from message com.secforce.droidground.Response
 */
export type Response = Message<"com.secforce.droidground.Response"> & {
  /**
   * @generated from field: string id = 1;
   */
  id: string;

  /**
   * @generated from field: string result = 2;
   */
  result: string;
};

/**
 * Describes the message com.secforce.droidground.Response.
 * Use `create(ResponseSchema)` to create a new message.
 */
export const ResponseSchema: GenMessage<Response> = /*@__PURE__*/
  messageDesc(file_wire, 1);

