/**
 * Helper function to enumerate all declared methods of a class.
 *
 * @param {string} targetClass - Fully qualified Java class name.
 * @returns {string[]} Array of method signatures.
 */
function enumMethods(targetClass) {
  var hook = Java.use(targetClass);
  var ownMethods = hook.class.getDeclaredMethods();
  hook.$dispose();

  return ownMethods.map(method => method.toString());
}

/**
 * Enumerate all methods declared in a given Java class.
 *
 * @param {Object} args - An object containing parameters.
 * @param {string} args.className - Fully qualified Java class name (e.g., "java.lang.String").
 * @returns {void}
 */
rpc.exports = {
  run: function (args) {
    const { className } = args;
    var result = [];
    Java.perform(function () {
      result = enumMethods(className);
      result.forEach(function (el) {
        send(el);
      });
    });
  },
  schema: function () {
    return {
      type: "object",
      properties: {
        className: { type: "string" },
      },
      required: ["className"],
      additionalProperties: false,
    };
  },
};
