/**
 * This Frida script intercepts and logs all calls to Android's logging functions at both the Java and native layers
 *
 * @returns {void}
 */

import Java from "frida-java-bridge";

rpc.exports = {
  run: function () {
    Java.performNow(function () {
      let Log = Java.use("android.util.Log");
      Log.d.overload("java.lang.String", "java.lang.String").implementation = function (a, b) {
        send(a.toString());
        send(b.toString());
        return this.d(a, b);
      };
      Log.d.overload("java.lang.String", "java.lang.String", "java.lang.Throwable").implementation = function (
        a,
        b,
        c,
      ) {
        send(a.toString());
        send(b.toString());
        return this.d(a, b, c);
      };
      Log.v.overload("java.lang.String", "java.lang.String").implementation = function (a, b) {
        send(a.toString());
        send(b.toString());
        return this.v(a, b);
      };
      Log.v.overload("java.lang.String", "java.lang.String", "java.lang.Throwable").implementation = function (
        a,
        b,
        c,
      ) {
        send(a.toString());
        send(b.toString());
        return this.v(a, b, c);
      };
      Log.i.overload("java.lang.String", "java.lang.String").implementation = function (a, b) {
        send(a.toString());
        send(b.toString());
        return this.i(a, b);
      };
      Log.i.overload("java.lang.String", "java.lang.String", "java.lang.Throwable").implementation = function (
        a,
        b,
        c,
      ) {
        send(a.toString());
        send(b.toString());
        return this.i(a, b, c);
      };
      Log.e.overload("java.lang.String", "java.lang.String").implementation = function (a, b) {
        send(a.toString());
        send(b.toString());
        return this.e(a, b);
      };
      Log.e.overload("java.lang.String", "java.lang.String", "java.lang.Throwable").implementation = function (
        a,
        b,
        c,
      ) {
        send(a.toString());
        send(b.toString());
        return this.e(a, b, c);
      };
      Log.w.overload("java.lang.String", "java.lang.String").implementation = function (a, b) {
        send(a.toString());
        send(b.toString());
        return this.w(a, b);
      };
      Log.w.overload("java.lang.String", "java.lang.Throwable").implementation = function (a, b) {
        send(a.toString());
        return this.w(a, b);
      };
      Log.w.overload("java.lang.String", "java.lang.String", "java.lang.Throwable").implementation = function (
        a,
        b,
        c,
      ) {
        send(a.toString());
        send(b.toString());
        return this.w(a, b, c);
      };
      Log.wtf.overload("java.lang.String", "java.lang.String").implementation = function (a, b) {
        send(a.toString());
        send(b.toString());
        return this.wtf.overload("java.lang.String", "java.lang.String").call(this, a, b);
      };
      Log.println.overload("int", "java.lang.String", "java.lang.String").implementation = function (a, b, c) {
        send(a.toString());
        send(b.toString());
        send(c.toString());
        return this.println(a, b, c);
      };
    });
    let LogPrint = Module.findExportByName("liblog.so", "__android_log_print");
    let LogWrite = Module.findExportByName("liblog.so", "__android_log_write");
    let LogVPrint = Module.findExportByName("liblog.so", "__android_log_vprint");
    let LogAssert = Module.findExportByName("liblog.so", "__android_log_assert");
    Interceptor.attach(LogPrint, function (args) {
      send("Print : ", args[1].readCString(), args[2].readCString());
    });
    Interceptor.attach(LogWrite, function (args) {
      send("Write : ", args[1].readCString(), args[2].readCString());
    });
    Interceptor.attach(LogVPrint, function (args) {
      send("VPrint : ", args[1].readCString(), args[2].readCString());
    });
    Interceptor.attach(LogAssert, function (args) {
      send("Assert : ", args[0].readCString(), args[1].readCString());
    });
  },
  schema: function () {
    return null;
  },
};
