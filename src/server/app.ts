import fs from "fs/promises";
import { v4 as uuidv4 } from "uuid";
import { Server as HTTPServer } from "http";
import express from "express";
import { Application as ExpressApplication } from "express";
import cors from "cors";
import { WebSocketServer, WebSocket } from "ws";
import "@dotenvx/dotenvx/config";
import frida, { FileDescriptor, ProcessID } from "frida";
import Ajv from "ajv";

// '@yume-chan' imports
import { Adb, decodeUtf8, encodeUtf8 } from "@yume-chan/adb";

// Local imports
import { ManagerSingleton } from "@server/manager";
import api from "@server/api";
import { StreamingPhase, WSMessageType } from "@shared/types";
import Logger from "@server/utils/logger";
import { IFridaRPC, WebsocketClient } from "@server/utils/types";
import { sendStructuredMessage } from "@server/utils/ws";
import { libraryFile, resourceFile, safeFileExists } from "@server/utils/helpers";
import { RESOURCES } from "@server/config";
import { WEBSOCKET_ENDPOINTS } from "@shared/endpoints";
import { setupFrida } from "@server/utils/frida";
import { StartFridaLibraryScriptRequest } from "@shared/api";
import { setupScrcpy } from "./utils/scrcpy";

const setupApi = async (app: ExpressApplication) => {
  app.use(
    cors({
      exposedHeaders: ["Content-Disposition"],
    }),
  );
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  // Load routes
  app.use("/api/v1", api());
};

const setupWs = async (httpServer: HTTPServer) => {
  const singleton = ManagerSingleton.getInstance();
  const features = singleton.getConfig().features;
  const fridaType = features.fridaType;

  const wssStreaming = new WebSocketServer({ noServer: true });
  const wssTerminal = new WebSocketServer({ noServer: true });
  const wssFrida = new WebSocketServer({ noServer: true });

  const wsStreamingClients = singleton.wsStreamingClients;
  const wsTerminalSessions = singleton.wsTerminalSessions;
  const wsFridaSessions = singleton.wsFridaSessions;

  // Handle upgrade requests
  httpServer.on("upgrade", (request, socket, head) => {
    if (request.url === WEBSOCKET_ENDPOINTS.STREAMING) {
      wssStreaming.handleUpgrade(request, socket, head, ws => {
        wssStreaming.emit("connection", ws, request);
      });
    } else if (request.url === WEBSOCKET_ENDPOINTS.TERMINAL && features.terminalEnabled) {
      wssTerminal.handleUpgrade(request, socket, head, ws => {
        wssTerminal.emit("connection", ws, request);
      });
    } else if (request.url === WEBSOCKET_ENDPOINTS.FRIDA && features.fridaEnabled) {
      wssFrida.handleUpgrade(request, socket, head, ws => {
        wssFrida.emit("connection", ws, request);
      });
    } else {
      socket.destroy();
    }
  });

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

  wssTerminal.on("connection", async (ws: WebSocket) => {
    try {
      // 1. Get ADB device
      const adb: Adb = await ManagerSingleton.getInstance().getAdb();

      // 2. Create PTY shell
      const ptyProcess = await adb.subprocess.shellProtocol!.pty();

      void ptyProcess.exited
        .then(exitCode => {
          Logger.debug(`PTY process exited with code ${exitCode}`);
          wsTerminalSessions.delete(ws);
          ws.send("[Process exited]");
          ws.close();
        })
        .catch(() => {
          Logger.debug("PTY process killed");
        });

      wsTerminalSessions.set(ws, { process });

      // 3. Start output reader loop
      const reader = ptyProcess.output.getReader();
      (async () => {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          ws.send(decodeUtf8(value));
        }
      })().catch(Logger.error);

      // 4. Handle input from user
      const writer = ptyProcess.input.getWriter();
      ws.on("message", async msg => {
        await writer.write(encodeUtf8(msg.toString()));
      });

      // 5. Cleanup
      ws.on("close", async () => {
        Logger.info("Client disconnected");
        wsTerminalSessions.delete(ws);
        await ptyProcess.kill();
      });
    } catch (err) {
      Logger.error(`Error initializing session: ${err}`);
      ws.send(`Error: ${err}`);
      ws.close();
    }
  });

  wssStreaming.on("connection", (ws: WebSocket) => {
    const id = uuidv4();
    wsStreamingClients.set(id, {
      state: StreamingPhase.INIT,
      ws: ws,
    });

    Logger.info(`WebSocket Streaming client connected with id '${id}', sending Metadata message (if available)`);

    if (singleton.sharedVideoMetadata) {
      sendStructuredMessage(ws, WSMessageType.STREAM_METADATA, singleton.sharedVideoMetadata);
    }

    ws.on("message", (clientMessage: any) => {
      const singleton = ManagerSingleton.getInstance();
      let message = clientMessage.toString();
      const currentClientData = wsStreamingClients.get(id) as WebsocketClient;
      switch (message) {
        case WSMessageType.STREAM_METADATA_ACK:
          wsStreamingClients.set(id, { ...(currentClientData as WebsocketClient), state: StreamingPhase.METADATA });
          if (singleton.sharedConfiguration) {
            sendStructuredMessage(ws, WSMessageType.CONFIGURATION, {}, singleton.sharedConfiguration.data);
          }
          break;
        case WSMessageType.CONFIGURATION_ACK:
          const nextState: StreamingPhase =
            singleton.sharedVideoMetadata?.hardwareType === "hardware"
              ? StreamingPhase.KEYFRAME
              : StreamingPhase.RENDER;
          wsStreamingClients.set(id, { ...(currentClientData as WebsocketClient), state: nextState });
          break;
        default:
          Logger.error(`Unknown message type: ${message}`);
          break;
      }
    });

    ws.on("close", () => {
      wsStreamingClients.delete(id);
      Logger.info(`WebSocket client with id '${id}' disconnected`);
    });
  });
};

const checkResources = () => {
  Logger.debug("Check resources...");
  const companionFile = resourceFile(RESOURCES.COMPANION_FILE);
  const scrcpyFile = resourceFile(RESOURCES.SCRCPY_SERVER);
  if (!safeFileExists(companionFile)) {
    Logger.error(`Companion file is missing, run 'npm run companion' to generate it`);
    process.exit(1);
  }
  if (!safeFileExists(scrcpyFile)) {
    Logger.error(`Scrcpy server is missing, run 'npm run scrcpy' to generate it`);
    process.exit(1);
  }
  Logger.debug("Check resources done!");
};

export const serverApp = async (app: ExpressApplication, httpServer: HTTPServer) => {
  checkResources();
  const manager = ManagerSingleton.getInstance();

  await manager.init(httpServer);
  // A device is needed, otherwise there's nothing to do here

  await manager.setAdb();
  manager.setCtf();

  if (manager.getConfig().features.fridaEnabled) {
    await setupFrida();
  }

  await manager.runTargetApp(); // Start the target app
  await setupApi(app);
  await setupWs(httpServer);
  await setupScrcpy();
};
