/**
 * Debugger connected Bypass
 *
 * @returns {void}
 */
rpc.exports = {
  run: function () {
    Java.perform(function () {
      send("--> isDebuggerConnected - Bypass Loaded");
      var Debug = Java.use("android.os.Debug");
      Debug.isDebuggerConnected.implementation = function () {
        send("isDebuggerConnected - bypass done!");
        return false;
      };
    });
  },
  schema: function () {
    return null;
  },
};
