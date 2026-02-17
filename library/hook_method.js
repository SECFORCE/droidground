/**
 * Dynamically hooks all overloads of a specified Java method in an Android app,
 * logs its invocation and arguments, and replaces its arguments with user-specified ones.
 *
 * @param {Object} args - The input arguments for the hook.
 * @param {string} args.className - Fully-qualified name of the Java class to hook (e.g., "com.example.MyClass").
 * @param {string} args.methodName - Name of the method in the class to hook.
 * @param {Array<any>} args.fnArgs - Array of values to overwrite the original method arguments with.
 *
 */

import Java from "frida-java-bridge";

rpc.exports = {
  run: function (args) {
    const { className, methodName, fnArgs } = args;
    Java.perform(function () {
      var TargetClass = Java.use(className);

      // Get all overloads of the method
      var overloads = TargetClass[methodName].overloads;

      send("[*] Hooking " + overloads.length + " overload(s) of " + className + "." + methodName);

      overloads.forEach(function (overload) {
        overload.implementation = function () {
          send("\n[>] Called " + className + "." + methodName);
          send("    ↪ Overload: " + overload.argumentTypes.map(t => t.className).join(", "));

          // Log arguments
          for (var i = 0; i < arguments.length; i++) {
            send("    ↳ arg[" + i + "]: " + arguments[i]);
          }

          for (var i = 0; i < fnArgs.length; i++) {
            arguments[i] = fnArgs[i];
          }

          // Call original method
          overload.apply(this, arguments);
        };
      });
    });
  },
  schema: function () {
    return {
      type: "object",
      properties: {
        className: { type: "string" },
        methodName: { type: "string" },
        fnArgs: {
          type: "array",
          items: {}, // Accepts any types
        },
      },
      required: ["className", "methodName", "fnArgs"],
      additionalProperties: false,
    };
  },
};
