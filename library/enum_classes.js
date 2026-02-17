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

rpc.exports = {
  /**
   * Enumerate all loaded Java class names in dot notation.
   *
   * @returns {void}
   */
  run: function () {
    var result = [];
    Java.perform(function () {
      result = enumAllClasses();
      result.forEach(function (el) {
        send(el);
      });
    });
  },
  schema: function () {
    return null;
  },
};
