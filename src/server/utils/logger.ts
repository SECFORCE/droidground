import { pino } from "pino";

const transports = pino.transport({
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
