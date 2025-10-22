import { pino, transport } from "pino";

const transports = transport({
  targets: [
    {
      level: "debug",
      target: "pino-pretty",
      options: {},
    },
  ],
});

const l = pino(
  {
    name: "droidground",
    level: "trace",
    customLevels: {
      http: 15,
    },
  },
  transports,
);

export default l;
