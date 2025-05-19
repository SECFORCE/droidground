/*eslint-disable block-scoped-var, id-length, no-control-regex, no-magic-numbers, no-prototype-builtins, no-redeclare, no-shadow, no-var, sort-vars*/
import $protobuf from "protobufjs/minimal";

// Common aliases
const $Reader = $protobuf.Reader,
  $Writer = $protobuf.Writer,
  $util = $protobuf.util;

// Exported root namespace
const $root = $protobuf.roots["default"] || ($protobuf.roots["default"] = {});

export const com = ($root.com = (() => {
  /**
   * Namespace com.
   * @exports com
   * @namespace
   */
  const com = {};

  com.secforce = (function () {
    /**
     * Namespace secforce.
     * @memberof com
     * @namespace
     */
    const secforce = {};

    secforce.droidground = (function () {
      /**
       * Namespace droidground.
       * @memberof com.secforce
       * @namespace
       */
      const droidground = {};

      droidground.Request = (function () {
        /**
         * Properties of a Request.
         * @memberof com.secforce.droidground
         * @interface IRequest
         * @property {string|null} [id] Request id
         * @property {string|null} [method] Request method
         * @property {string|null} [params] Request params
         */

        /**
         * Constructs a new Request.
         * @memberof com.secforce.droidground
         * @classdesc Represents a Request.
         * @implements IRequest
         * @constructor
         * @param {com.secforce.droidground.IRequest=} [properties] Properties to set
         */
        function Request(properties) {
          if (properties)
            for (let keys = Object.keys(properties), i = 0; i < keys.length; ++i)
              if (properties[keys[i]] != null) this[keys[i]] = properties[keys[i]];
        }

        /**
         * Request id.
         * @member {string} id
         * @memberof com.secforce.droidground.Request
         * @instance
         */
        Request.prototype.id = "";

        /**
         * Request method.
         * @member {string} method
         * @memberof com.secforce.droidground.Request
         * @instance
         */
        Request.prototype.method = "";

        /**
         * Request params.
         * @member {string} params
         * @memberof com.secforce.droidground.Request
         * @instance
         */
        Request.prototype.params = "";

        /**
         * Creates a new Request instance using the specified properties.
         * @function create
         * @memberof com.secforce.droidground.Request
         * @static
         * @param {com.secforce.droidground.IRequest=} [properties] Properties to set
         * @returns {com.secforce.droidground.Request} Request instance
         */
        Request.create = function create(properties) {
          return new Request(properties);
        };

        /**
         * Encodes the specified Request message. Does not implicitly {@link com.secforce.droidground.Request.verify|verify} messages.
         * @function encode
         * @memberof com.secforce.droidground.Request
         * @static
         * @param {com.secforce.droidground.IRequest} message Request message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        Request.encode = function encode(message, writer) {
          if (!writer) writer = $Writer.create();
          if (message.id != null && Object.hasOwnProperty.call(message, "id"))
            writer.uint32(/* id 1, wireType 2 =*/ 10).string(message.id);
          if (message.method != null && Object.hasOwnProperty.call(message, "method"))
            writer.uint32(/* id 2, wireType 2 =*/ 18).string(message.method);
          if (message.params != null && Object.hasOwnProperty.call(message, "params"))
            writer.uint32(/* id 3, wireType 2 =*/ 26).string(message.params);
          return writer;
        };

        /**
         * Encodes the specified Request message, length delimited. Does not implicitly {@link com.secforce.droidground.Request.verify|verify} messages.
         * @function encodeDelimited
         * @memberof com.secforce.droidground.Request
         * @static
         * @param {com.secforce.droidground.IRequest} message Request message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        Request.encodeDelimited = function encodeDelimited(message, writer) {
          return this.encode(message, writer).ldelim();
        };

        /**
         * Decodes a Request message from the specified reader or buffer.
         * @function decode
         * @memberof com.secforce.droidground.Request
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @param {number} [length] Message length if known beforehand
         * @returns {com.secforce.droidground.Request} Request
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        Request.decode = function decode(reader, length, error) {
          if (!(reader instanceof $Reader)) reader = $Reader.create(reader);
          let end = length === undefined ? reader.len : reader.pos + length,
            message = new $root.com.secforce.droidground.Request();
          while (reader.pos < end) {
            let tag = reader.uint32();
            if (tag === error) break;
            switch (tag >>> 3) {
              case 1: {
                message.id = reader.string();
                break;
              }
              case 2: {
                message.method = reader.string();
                break;
              }
              case 3: {
                message.params = reader.string();
                break;
              }
              default:
                reader.skipType(tag & 7);
                break;
            }
          }
          return message;
        };

        /**
         * Decodes a Request message from the specified reader or buffer, length delimited.
         * @function decodeDelimited
         * @memberof com.secforce.droidground.Request
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @returns {com.secforce.droidground.Request} Request
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        Request.decodeDelimited = function decodeDelimited(reader) {
          if (!(reader instanceof $Reader)) reader = new $Reader(reader);
          return this.decode(reader, reader.uint32());
        };

        /**
         * Verifies a Request message.
         * @function verify
         * @memberof com.secforce.droidground.Request
         * @static
         * @param {Object.<string,*>} message Plain object to verify
         * @returns {string|null} `null` if valid, otherwise the reason why it is not
         */
        Request.verify = function verify(message) {
          if (typeof message !== "object" || message === null) return "object expected";
          if (message.id != null && message.hasOwnProperty("id"))
            if (!$util.isString(message.id)) return "id: string expected";
          if (message.method != null && message.hasOwnProperty("method"))
            if (!$util.isString(message.method)) return "method: string expected";
          if (message.params != null && message.hasOwnProperty("params"))
            if (!$util.isString(message.params)) return "params: string expected";
          return null;
        };

        /**
         * Creates a Request message from a plain object. Also converts values to their respective internal types.
         * @function fromObject
         * @memberof com.secforce.droidground.Request
         * @static
         * @param {Object.<string,*>} object Plain object
         * @returns {com.secforce.droidground.Request} Request
         */
        Request.fromObject = function fromObject(object) {
          if (object instanceof $root.com.secforce.droidground.Request) return object;
          let message = new $root.com.secforce.droidground.Request();
          if (object.id != null) message.id = String(object.id);
          if (object.method != null) message.method = String(object.method);
          if (object.params != null) message.params = String(object.params);
          return message;
        };

        /**
         * Creates a plain object from a Request message. Also converts values to other types if specified.
         * @function toObject
         * @memberof com.secforce.droidground.Request
         * @static
         * @param {com.secforce.droidground.Request} message Request
         * @param {$protobuf.IConversionOptions} [options] Conversion options
         * @returns {Object.<string,*>} Plain object
         */
        Request.toObject = function toObject(message, options) {
          if (!options) options = {};
          let object = {};
          if (options.defaults) {
            object.id = "";
            object.method = "";
            object.params = "";
          }
          if (message.id != null && message.hasOwnProperty("id")) object.id = message.id;
          if (message.method != null && message.hasOwnProperty("method")) object.method = message.method;
          if (message.params != null && message.hasOwnProperty("params")) object.params = message.params;
          return object;
        };

        /**
         * Converts this Request to JSON.
         * @function toJSON
         * @memberof com.secforce.droidground.Request
         * @instance
         * @returns {Object.<string,*>} JSON object
         */
        Request.prototype.toJSON = function toJSON() {
          return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
        };

        /**
         * Gets the default type url for Request
         * @function getTypeUrl
         * @memberof com.secforce.droidground.Request
         * @static
         * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
         * @returns {string} The default type url
         */
        Request.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
          if (typeUrlPrefix === undefined) {
            typeUrlPrefix = "type.googleapis.com";
          }
          return typeUrlPrefix + "/com.secforce.droidground.Request";
        };

        return Request;
      })();

      droidground.Response = (function () {
        /**
         * Properties of a Response.
         * @memberof com.secforce.droidground
         * @interface IResponse
         * @property {string|null} [id] Response id
         * @property {string|null} [result] Response result
         */

        /**
         * Constructs a new Response.
         * @memberof com.secforce.droidground
         * @classdesc Represents a Response.
         * @implements IResponse
         * @constructor
         * @param {com.secforce.droidground.IResponse=} [properties] Properties to set
         */
        function Response(properties) {
          if (properties)
            for (let keys = Object.keys(properties), i = 0; i < keys.length; ++i)
              if (properties[keys[i]] != null) this[keys[i]] = properties[keys[i]];
        }

        /**
         * Response id.
         * @member {string} id
         * @memberof com.secforce.droidground.Response
         * @instance
         */
        Response.prototype.id = "";

        /**
         * Response result.
         * @member {string} result
         * @memberof com.secforce.droidground.Response
         * @instance
         */
        Response.prototype.result = "";

        /**
         * Creates a new Response instance using the specified properties.
         * @function create
         * @memberof com.secforce.droidground.Response
         * @static
         * @param {com.secforce.droidground.IResponse=} [properties] Properties to set
         * @returns {com.secforce.droidground.Response} Response instance
         */
        Response.create = function create(properties) {
          return new Response(properties);
        };

        /**
         * Encodes the specified Response message. Does not implicitly {@link com.secforce.droidground.Response.verify|verify} messages.
         * @function encode
         * @memberof com.secforce.droidground.Response
         * @static
         * @param {com.secforce.droidground.IResponse} message Response message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        Response.encode = function encode(message, writer) {
          if (!writer) writer = $Writer.create();
          if (message.id != null && Object.hasOwnProperty.call(message, "id"))
            writer.uint32(/* id 1, wireType 2 =*/ 10).string(message.id);
          if (message.result != null && Object.hasOwnProperty.call(message, "result"))
            writer.uint32(/* id 2, wireType 2 =*/ 18).string(message.result);
          return writer;
        };

        /**
         * Encodes the specified Response message, length delimited. Does not implicitly {@link com.secforce.droidground.Response.verify|verify} messages.
         * @function encodeDelimited
         * @memberof com.secforce.droidground.Response
         * @static
         * @param {com.secforce.droidground.IResponse} message Response message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        Response.encodeDelimited = function encodeDelimited(message, writer) {
          return this.encode(message, writer).ldelim();
        };

        /**
         * Decodes a Response message from the specified reader or buffer.
         * @function decode
         * @memberof com.secforce.droidground.Response
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @param {number} [length] Message length if known beforehand
         * @returns {com.secforce.droidground.Response} Response
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        Response.decode = function decode(reader, length, error) {
          if (!(reader instanceof $Reader)) reader = $Reader.create(reader);
          let end = length === undefined ? reader.len : reader.pos + length,
            message = new $root.com.secforce.droidground.Response();
          while (reader.pos < end) {
            let tag = reader.uint32();
            if (tag === error) break;
            switch (tag >>> 3) {
              case 1: {
                message.id = reader.string();
                break;
              }
              case 2: {
                message.result = reader.string();
                break;
              }
              default:
                reader.skipType(tag & 7);
                break;
            }
          }
          return message;
        };

        /**
         * Decodes a Response message from the specified reader or buffer, length delimited.
         * @function decodeDelimited
         * @memberof com.secforce.droidground.Response
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @returns {com.secforce.droidground.Response} Response
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        Response.decodeDelimited = function decodeDelimited(reader) {
          if (!(reader instanceof $Reader)) reader = new $Reader(reader);
          return this.decode(reader, reader.uint32());
        };

        /**
         * Verifies a Response message.
         * @function verify
         * @memberof com.secforce.droidground.Response
         * @static
         * @param {Object.<string,*>} message Plain object to verify
         * @returns {string|null} `null` if valid, otherwise the reason why it is not
         */
        Response.verify = function verify(message) {
          if (typeof message !== "object" || message === null) return "object expected";
          if (message.id != null && message.hasOwnProperty("id"))
            if (!$util.isString(message.id)) return "id: string expected";
          if (message.result != null && message.hasOwnProperty("result"))
            if (!$util.isString(message.result)) return "result: string expected";
          return null;
        };

        /**
         * Creates a Response message from a plain object. Also converts values to their respective internal types.
         * @function fromObject
         * @memberof com.secforce.droidground.Response
         * @static
         * @param {Object.<string,*>} object Plain object
         * @returns {com.secforce.droidground.Response} Response
         */
        Response.fromObject = function fromObject(object) {
          if (object instanceof $root.com.secforce.droidground.Response) return object;
          let message = new $root.com.secforce.droidground.Response();
          if (object.id != null) message.id = String(object.id);
          if (object.result != null) message.result = String(object.result);
          return message;
        };

        /**
         * Creates a plain object from a Response message. Also converts values to other types if specified.
         * @function toObject
         * @memberof com.secforce.droidground.Response
         * @static
         * @param {com.secforce.droidground.Response} message Response
         * @param {$protobuf.IConversionOptions} [options] Conversion options
         * @returns {Object.<string,*>} Plain object
         */
        Response.toObject = function toObject(message, options) {
          if (!options) options = {};
          let object = {};
          if (options.defaults) {
            object.id = "";
            object.result = "";
          }
          if (message.id != null && message.hasOwnProperty("id")) object.id = message.id;
          if (message.result != null && message.hasOwnProperty("result")) object.result = message.result;
          return object;
        };

        /**
         * Converts this Response to JSON.
         * @function toJSON
         * @memberof com.secforce.droidground.Response
         * @instance
         * @returns {Object.<string,*>} JSON object
         */
        Response.prototype.toJSON = function toJSON() {
          return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
        };

        /**
         * Gets the default type url for Response
         * @function getTypeUrl
         * @memberof com.secforce.droidground.Response
         * @static
         * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
         * @returns {string} The default type url
         */
        Response.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
          if (typeUrlPrefix === undefined) {
            typeUrlPrefix = "type.googleapis.com";
          }
          return typeUrlPrefix + "/com.secforce.droidground.Response";
        };

        return Response;
      })();

      return droidground;
    })();

    return secforce;
  })();

  return com;
})());

export { $root as default };
