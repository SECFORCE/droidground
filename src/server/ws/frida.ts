import fs from "fs/promises";
import { WebSocketServer, WebSocket, RawData } from "ws";
import path from "path";
import frida, { FileDescriptor, ProcessID } from "frida";
import Ajv from "ajv";
import { ManagerSingleton } from "@server/manager";
import Logger from "@shared/logger";
import { IFridaRPC } from "@server/utils/types";
import { fridaScriptsDir, libraryFile } from "@server/utils/helpers";
import { StartFridaFullScriptRequest, StartFridaLibraryScriptRequest } from "@shared/api";
import { startFridaFullScriptSchema, startFridaLibraryScriptSchema } from "@server/ws/schemas";
import { sleep } from "@shared/helpers";

type WsFridaSessionState = {
  device: frida.Device;
  pid: ProcessID | null;
  script: frida.Script | null;
};

const ajv = new Ajv();

const parseFullWsMessage = (msg: RawData): StartFridaFullScriptRequest | undefined => {
  try {
    const msgObject = JSON.parse(msg.toString());
    const isValid = ajv.validate(startFridaFullScriptSchema, msgObject);
    if (!isValid) {
      throw new Error("Object content is not valid");
    }
    return msgObject as StartFridaFullScriptRequest;
  } catch (e) {
    Logger.error(`Unable to parse WebSocket message: ${e}`);
  }
};

const parseJailedWsMessage = (msg: RawData): StartFridaLibraryScriptRequest | undefined => {
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

const buildBundleFromInlineCode = async (
  code: string,
  language: string,
): Promise<{ bundle: string; entryAbs: string }> => {
  const compiler = new frida.Compiler();
  const filename = `agent-${crypto.randomUUID()}.${language}`;
  const entryAbs = path.resolve(fridaScriptsDir(), filename);
  await fs.writeFile(entryAbs, code, "utf8");
  const bundle = await compiler.build(entryAbs);
  return { bundle, entryAbs };
};

const buildBundleFromLibrary = async (scriptName: string): Promise<string> => {
  const compiler = new frida.Compiler();
  return compiler.build(libraryFile(scriptName));
};

const runLibraryRpc = async (script: frida.Script, args?: unknown) => {
  const rpc = script.exports as IFridaRPC;
  const schema = await rpc.schema();

  if (!schema) {
    await rpc.run(); // If the schema is missing run without args
    return;
  }

  const valid = ajv.validate(schema, args);

  if (!valid) {
    throw new Error("Inputs are invalid for the selected Frida script");
  }

  await rpc.run(args);
};

export const setupFridaWss = (wssFrida: WebSocketServer) => {
  const singleton = ManagerSingleton.getInstance();
  const config = singleton.getConfig();
  const fridaType = config.features.fridaType;
  const packageName = config.packageName;
  const wsFridaSessions = singleton.wsFridaSessions;

  wssFrida.on("connection", (ws: WebSocket) => {
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

    const setSessionState = (partial: Partial<WsFridaSessionState> | null) => {
      if (partial === null) {
        wsFridaSessions.set(ws, null);
        return;
      }
      const current = (wsFridaSessions.get(ws) ?? null) as WsFridaSessionState | null;
      const next = { ...(current ?? {}), ...partial } as WsFridaSessionState;
      wsFridaSessions.set(ws, next);
    };

    const getSessionState = () => (wsFridaSessions.get(ws) ?? null) as WsFridaSessionState | null;

    const spawnApp = async (device: frida.Device): Promise<{ session: frida.Session; pid: ProcessID }> => {
      let session: frida.Session;
      let pid: ProcessID;
      if (config.features.fridaInjection === "server") {
        pid = await device.spawn(packageName);
        session = await device.attach(pid);
      } else {
        const singleton = ManagerSingleton.getInstance();
        await singleton.runTargetApp();
        await sleep(1000); // Give the app some time to start and be detected by Frida
        const frontmost = await device.getFrontmostApplication();

        if (!frontmost || frontmost.identifier !== packageName) {
          throw new Error("Target app is not running or in foreground");
        }

        pid = frontmost.pid;
        session = await device.attach(pid);
      }
      return { session, pid };
    };

    const prepareDeviceSession = async (): Promise<{
      device: frida.Device;
      pid: ProcessID;
      session: frida.Session;
    }> => {
      const device = await frida.getUsbDevice();

      setSessionState({ device, pid: null, script: null });
      device.output.connect(onOutput);

      const { pid, session } = await spawnApp(device);

      setSessionState({ pid });
      session.detached.connect(onDetached);

      return { device, pid, session };
    };

    ws.once("message", async msg => {
      let entryAbs: string | undefined;
      let device: frida.Device | undefined;
      let pid: ProcessID | null = null;

      try {
        if (fridaType === "full") {
          /*
           * Frida full
           */
          const wsObj = parseFullWsMessage(msg);
          if (!wsObj) {
            return;
          }

          const { code, language } = wsObj;
          const { bundle, entryAbs: tmpFile } = await buildBundleFromInlineCode(code, language);
          entryAbs = tmpFile;

          const prepared = await prepareDeviceSession();
          device = prepared.device;
          pid = prepared.pid;

          const script = await prepared.session.createScript(bundle);
          setSessionState({ script });
          script.message.connect(onMessage);

          await script.load();
        } else {
          /*
           * Frida jailed
           */
          const wsObj = parseJailedWsMessage(msg);
          if (!wsObj) {
            return;
          }

          const { scriptName, args } = wsObj;
          const bundle = await buildBundleFromLibrary(scriptName);

          const prepared = await prepareDeviceSession();
          device = prepared.device;
          pid = prepared.pid;

          const script = await prepared.session.createScript(bundle);
          setSessionState({ script });

          script.message.connect(onMessage);
          await script.load();

          await runLibraryRpc(script, args);
        }
      } catch (err) {
        ws.send(`An error occurred while running Frida script`);
        Logger.error(`An error occurred while running the script: ${err}`);
      } finally {
        const fallbackState = getSessionState();
        const deviceToResume = device ?? fallbackState?.device;
        const pidToResume = pid ?? fallbackState?.pid ?? null;

        if (deviceToResume && pidToResume) {
          Logger.info(`Resuming (${pidToResume})`);
          await deviceToResume.resume(pidToResume);
        }

        if (entryAbs) {
          await fs.rm(entryAbs, { force: true }).catch(() => {});
        }
      }
    });

    ws.on("close", async () => {
      Logger.info("Client disconnected");
      const sessionState = getSessionState();

      // Prevent output listener leaks.
      sessionState?.device?.output?.disconnect(onOutput);

      // Best-effort cleanup: unloading can fail if the session is already detached.
      await sessionState?.script?.unload().catch(() => {});

      wsFridaSessions.delete(ws);
    });
  });
};
