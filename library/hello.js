rpc.exports = {
  /**
   * Just a simple Hello World script (for testing purposes).
   *
   * @returns {void}
   */
  run: function () {
    setImmediate(function () {
      send("Hello, world!");
    });
  },
  schema: function () {
    return null;
  },
};
