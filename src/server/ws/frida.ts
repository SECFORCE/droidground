import fs from "fs/promises";
import { WebSocketServer, WebSocket } from "ws";
import "@dotenvx/dotenvx/config";
import frida, { FileDescriptor, ProcessID } from "frida";
import Ajv from "ajv";

// Local imports
import { ManagerSingleton } from "@server/manager";
import Logger from "@server/utils/logger";
import { IFridaRPC } from "@server/utils/types";
import { libraryFile } from "@server/utils/helpers";

import { StartFridaLibraryScriptRequest } from "@shared/api";

export const setupFridaWss = (wssFrida: WebSocketServer) => {
  const singleton = ManagerSingleton.getInstance();
  const fridaType = singleton.getConfig().features.fridaType;
  const wsFridaSessions = singleton.wsFridaSessions;

  wssFrida.on("connection", (ws: WebSocket) => {
    ws.once("message", async msg => {
      try {
        const onOutput = (pid: ProcessID, fd: FileDescriptor, data: Buffer) => {
          if (pid !== wsFridaSessions.get(ws)?.pid) return;

          let description: string;
          if (data.length > 0) {
            description = '"' + data.toString().replace(/\n/g, "\\n") + '"';
          } else {
            description = "<EOF>";
          }
          Logger.info(`onOutput(pid=${pid}, fd=${fd}, data=${description})`);
        };

        const onDetached = (reason: frida.SessionDetachReason) => {
          Logger.info(`onDetached(reason="${reason}")`);
          wsFridaSessions.get(ws)?.device?.output.disconnect(onOutput);
          ws.close();
        };

        const onMessage = (m: frida.Message, data: Buffer | null) => {
          const message = m as frida.SendMessage;
          Logger.info(`[Frida message] Payload: ${message.payload} - Data: ${data}`);
          if (message.payload) {
            ws.send(message.payload);
          }
        };

        if (fridaType === "full") {
          /*
           * Frida full
           */
          const scriptContent = msg.toString();
          const device = await frida.getUsbDevice();

          wsFridaSessions.set(ws, { device: device, pid: null, script: null });
          device.output.connect(onOutput);

          const droidGroundConfig = ManagerSingleton.getInstance().getConfig();
          const pid = await device.spawn(droidGroundConfig.packageName);
          const session = await device.attach(pid);
          wsFridaSessions.set(ws, { device: device, pid: pid, script: null });

          session.detached.connect(onDetached);
          const script = await session.createScript(scriptContent);
          wsFridaSessions.set(ws, { device: device, pid: pid, script: script });
          script.message.connect(onMessage);

          await script.load();

          Logger.info(`Resuming (${pid})`);
          await device.resume(pid);
        } else {
          /*
           * Frida jailed
           */
          // TODO: Add body validation
          const { scriptName, args } = JSON.parse(msg.toString()) as StartFridaLibraryScriptRequest;
          const filename = libraryFile(scriptName);
          const scriptContent = await fs.readFile(filename, "utf-8");
          const device = await frida.getUsbDevice();

          wsFridaSessions.set(ws, { device: device, pid: null, script: null });
          device.output.connect(onOutput);
          const droidGroundConfig = ManagerSingleton.getInstance().getConfig();
          const pid = await device.spawn(droidGroundConfig.packageName);
          const session = await device.attach(pid);
          wsFridaSessions.set(ws, { device: device, pid: pid, script: null });

          session.detached.connect(onDetached);

          const script = await session.createScript(scriptContent);
          wsFridaSessions.set(ws, { device: device, pid: pid, script: script });

          script.message.connect(onMessage);
          await script.load();

          const rpc = script.exports as IFridaRPC;
          const schema = await rpc.schema();

          if (schema) {
            const ajv = new Ajv();
            const valid = ajv.validate(schema, args);
            if (!valid) {
              await device.resume(pid);
              throw new Error("Inputs are invalid for the selected Frida script");
            }
          }

          await rpc.run(args);
          Logger.info(`Resuming (${pid})`);
          await device.resume(pid);
        }
      } catch (err) {
        ws.send(`An error occurred while running Frida script`);
      }
    });

    ws.on("close", async () => {
      Logger.info("Client disconnected");
      await wsFridaSessions.get(ws)?.script?.unload();
      wsFridaSessions.delete(ws);
    });
  });
};
