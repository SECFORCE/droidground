// === Helper Functions ===

// generic trace
function trace(pattern) {
  var type = pattern.toString().indexOf("!") === -1 ? "java" : "module";

  if (type === "module") {
    // trace Module
    var res = new ApiResolver("module");
    var matches = res.enumerateMatchesSync(pattern);
    var targets = uniqBy(matches, JSON.stringify);
    targets.forEach(function (target) {
      traceModule(target.address, target.name);
    });
  } else if (type === "java") {
    // trace Java Class
    var found = false;
    Java.enumerateLoadedClasses({
      onMatch: function (aClass) {
        if (aClass.match(pattern)) {
          found = true;
          try {
            var className = aClass.match(/[L](.*);/)[1].replace(/\//g, ".");
            traceClass(className);
          } catch (_) {}
        }
      },
      onComplete: function () {},
    });

    // trace Java Method
    if (!found) {
      try {
        traceMethod(pattern);
      } catch (err) {
        send(err);
      }
    }
  }
}

// find and trace all methods declared in a Java Class
function traceClass(targetClass) {
  var hook = Java.use(targetClass);
  var methods = hook.class.getDeclaredMethods();
  hook.$dispose();

  var parsedMethods = [];
  methods.forEach(function (method) {
    try {
      var signature = method.toString().replace(targetClass + ".", "TOKEN");
      var parsed = signature.match(/\sTOKEN(.*)\(/)[1];
      parsedMethods.push(parsed);
    } catch (_) {}
  });

  var targets = uniqBy(parsedMethods, JSON.stringify);
  targets.forEach(function (targetMethod) {
    traceMethod(targetClass + "." + targetMethod);
  });
}

// trace a specific Java Method
function traceMethod(targetClassMethod) {
  var delim = targetClassMethod.lastIndexOf(".");
  if (delim === -1) return;

  var targetClass = targetClassMethod.slice(0, delim);
  var targetMethod = targetClassMethod.slice(delim + 1);

  var hook = Java.use(targetClass);
  var overloadCount = hook[targetMethod].overloads.length;

  send("Tracing " + targetClassMethod + " [" + overloadCount + " overload(s)]");

  for (var i = 0; i < overloadCount; i++) {
    hook[targetMethod].overloads[i].implementation = function () {
      send("\n*** entered " + targetClassMethod);

      // print arguments
      if (arguments.length) send();
      for (var j = 0; j < arguments.length; j++) {
        send("arg[" + j + "]: " + arguments[j]);
      }

      // call original method and print return value
      var retval = this[targetMethod].apply(this, arguments);
      send("\nretval: " + retval);
      send("\n*** exiting " + targetClassMethod);
      return retval;
    };
  }
}

// trace Module functions
function traceModule(impl, name) {
  send("Tracing " + name);

  Interceptor.attach(impl, {
    onEnter: function (args) {
      this.flag = false;

      // Example filters (disabled by default):
      // var filename = Memory.readCString(ptr(args[0]));
      // if (filename.indexOf("my.interesting.file") !== -1) this.flag = true;

      this.flag = true; // always trace for now

      if (this.flag) {
        send("\n*** entered " + name);
        send(
          "\nBacktrace:\n" +
            Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n"),
        );
      }
    },

    onLeave: function (retval) {
      if (this.flag) {
        send("\nretval: " + retval);
        send("\n*** exiting " + name);
      }
    },
  });
}

// remove duplicates from array
function uniqBy(array, key) {
  var seen = {};
  return array.filter(function (item) {
    var k = key(item);
    return seen.hasOwnProperty(k) ? false : (seen[k] = true);
  });
}

/**
 * Entry point to run a trace on a given pattern.
 * @param {Object} args - An object containing parameters.
 * @param {string} args.pattern - A pattern string to trace (Java class/method or module).
 *                                Supports exact names or regex (e.g., "com.example.Class", /decrypt/i, or "exports:*!open*").
 * @returns {void}
 */
rpc.exports = {
  run: function (args) {
    const { pattern } = args;
    Java.perform(function () {
      trace(pattern);
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
