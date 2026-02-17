/**
 * Get the unique ANDROID_ID for the target app
 *
 * @returns {void}
 */

import Java from "frida-java-bridge";

rpc.exports = {
  run: function () {
    Java.perform(function () {
      function getContext() {
        return Java.use("android.app.ActivityThread").currentApplication().getApplicationContext().getContentResolver();
      }
      send("[-]" + Java.use("android.provider.Settings$Secure").getString(getContext(), "android_id"));
    });
  },
  schema: function () {
    return null;
  },
};
