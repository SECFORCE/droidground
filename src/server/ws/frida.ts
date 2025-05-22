import fs from "fs/promises";
import { WebSocketServer, WebSocket, RawData } from "ws";
import frida, { FileDescriptor, ProcessID } from "frida";
import Ajv from "ajv";
import { ManagerSingleton } from "@server/manager";
import Logger from "@server/utils/logger";
import { IFridaRPC } from "@server/utils/types";
import { libraryFile } from "@server/utils/helpers";
import { StartFridaLibraryScriptRequest } from "@shared/api";
import { startFridaLibraryScriptSchema } from "@server/ws/schemas";

const ajv = new Ajv();

const parseWsMessage = (msg: RawData): StartFridaLibraryScriptRequest | undefined => {
  try {
    const msgObject = JSON.parse(msg.toString());
    const isValid = ajv.validate(startFridaLibraryScriptSchema, msgObject);
    if (!isValid) {
      throw new Error("Object content is not valid");
    }
    return msgObject as StartFridaLibraryScriptRequest;
  } catch (e) {
    Logger.error(`Unable to parse WebSocket message: ${e}`);
  }
};

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

        const onDetached = (reason: frida.SessionDetachReason, crash: frida.Crash | null) => {
          Logger.info(`onDetached(reason="${reason}")`);
          if (crash) {
            ws.send(crash.report);
          }
          wsFridaSessions.get(ws)?.device?.output.disconnect(onOutput);
          wsFridaSessions.set(ws, null);
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
          const wsObj = parseWsMessage(msg);
          if (!wsObj) {
            return;
          }

          const { scriptName, args } = wsObj;
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
              throw new Error("Inputs are invalid for the selected Frida script");
            }

            await rpc.run(args);
          } else {
            await rpc.run(); // If the schema is missing run without args
          }
        }
      } catch (err) {
        ws.send(`An error occurred while running Frida script`);
        Logger.error(`An error occurred while running the script: ${err}`);
      } finally {
        const currentSession = wsFridaSessions.get(ws);
        if (currentSession && currentSession.device && currentSession.pid) {
          const { device, pid } = currentSession;
          Logger.info(`Resuming (${pid})`);
          await device.resume(pid);
        }
      }
    });

    ws.on("close", async () => {
      Logger.info("Client disconnected");
      const session = wsFridaSessions.get(ws);
      if (session) {
        await wsFridaSessions.get(ws)?.script?.unload();
      }
      wsFridaSessions.delete(ws);
    });
  });
};
