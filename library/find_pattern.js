/**
 * Helper function to enumerate all loaded Java classes.
 *
 * @returns {string[]} Class names in dot notation (e.g., java.lang.String).
 */

import Java from "frida-java-bridge";

function enumAllClasses() {
  var allClasses = [];
  var classes = Java.enumerateLoadedClassesSync();

  classes.forEach(function (aClass) {
    try {
      var className = aClass.match(/[L](.*);/)[1].replace(/\//g, ".");
      allClasses.push(className);
    } catch (err) {
      // Ignore malformed class entries
    }
  });

  return allClasses;
}

/**
 * Find all Java classes that match a given regex pattern.
 *
 * @param {string} pattern - Regex pattern string.
 * @returns {string[]} Matching class names.
 */
function findClasses(pattern) {
  var allClasses = enumAllClasses();
  var foundClasses = [];

  var regex = new RegExp(pattern, "i");

  allClasses.forEach(function (aClass) {
    try {
      if (regex.test(aClass)) {
        foundClasses.push(aClass);
      }
    } catch (err) {
      // Ignore match errors
    }
  });

  return foundClasses;
}

rpc.exports = {
  /**
   * Find all loaded Java class names matching the provided pattern
   * and send them using Frida's `send()` function.
   *
   * @param {Object} args - An object containing parameters.
   * @param {string} args.pattern - Regex pattern string to match class names.
   * @returns {void}
   */
  run: function (args) {
    const { pattern } = args;
    Java.perform(function () {
      const matches = findClasses(pattern);
      matches.forEach(function (className) {
        send(className);
      });
    });
  },
  schema: function () {
    return {
      type: "object",
      properties: {
        pattern: { type: "string" },
      },
      required: ["pattern"],
      additionalProperties: false,
    };
  },
};
