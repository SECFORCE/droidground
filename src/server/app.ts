import path from "path";
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
import {
  DefaultServerPath,
  ScrcpyCodecOptions,
  ScrcpyMediaStreamConfigurationPacket,
  ScrcpyMediaStreamPacket,
} from "@yume-chan/scrcpy";
import { AdbScrcpyClient, AdbScrcpyOptions3_1 } from "@yume-chan/adb-scrcpy";
import { ReadableStream, WritableStream } from "@yume-chan/stream-extra";
import { TinyH264Decoder } from "@yume-chan/scrcpy-decoder-tinyh264";

// Local imports
import { ManagerSingleton } from "@server/manager";
import api from "@server/api";
import { DataMetadata, StreamingPhase, StreamMetadata, WSMessageType } from "@shared/types";
import Logger from "@server/utils/logger";
import { IFridaRPC, WebsocketClient } from "@server/utils/types";
import { broadcastForPhase, sendStructuredMessage } from "@server/utils/ws";
import { libraryFile, resourceFile, resourcesDir, safeFileExists } from "@server/utils/helpers";
import { DEFAULT_UPLOAD_FOLDER, RESOURCES } from "@server/config";
import { WEBSOCKET_ENDPOINTS } from "@shared/endpoints";
import { downloadFridaServer, getFridaVersion, mapAbiToFridaArch } from "@server/utils/frida";
import { StartFridaLibraryScriptRequest } from "@shared/api";

const H264Capabilities = TinyH264Decoder.capabilities.h264;

let sharedVideoMetadata: StreamMetadata | null = null;
let sharedConfiguration: ScrcpyMediaStreamConfigurationPacket | null = null;

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

const setupScrcpy = async () => {
  const scrcpyFile = resourceFile(RESOURCES.SCRCPY_SERVER);
  const serverBuffer: Buffer = await fs.readFile(scrcpyFile);
  const adb: Adb = await ManagerSingleton.getInstance().getAdb();
  const wsStreamingClients = ManagerSingleton.getInstance().wsStreamingClients;

  const sync = await adb.sync();
  try {
    await sync.write({
      filename: DefaultServerPath,
      file: new ReadableStream({
        start(controller) {
          controller.enqueue(new Uint8Array(serverBuffer));
          controller.close();
        },
      }),
    });
  } finally {
    await sync.dispose();
  }

  const encoders = await AdbScrcpyClient.getEncoders(
    adb,
    DefaultServerPath,
    new AdbScrcpyOptions3_1({
      listEncoders: true,
      cleanup: false,
    }),
  );

  // Choose first encoder for now
  const encoder = encoders.filter(e => e.type === "video")[0];
  const scrcpyClient = await AdbScrcpyClient.start(
    adb,
    DefaultServerPath,
    new AdbScrcpyOptions3_1({
      audio: false,
      control: false,
      videoCodec: "h264",
      videoBitRate: 10000000,
      videoEncoder: encoder.name,
      videoCodecOptions: new ScrcpyCodecOptions({
        iFrameInterval: 1,
        intraRefreshPeriod: 1,
        profile: H264Capabilities.maxProfile,
        level: H264Capabilities.maxLevel,
      }),
    }),
  );

  // Print output of Scrcpy server
  void scrcpyClient.output.pipeTo(
    new WritableStream<string>({
      write(chunk) {
        Logger.debug("Printing Scrcpy output");
        Logger.debug(chunk);
      },
    }),
  );

  if (scrcpyClient.videoStream) {
    const { metadata: videoMetadata, stream: videoPacketStream } = await scrcpyClient.videoStream;
    sharedVideoMetadata = {
      ...videoMetadata,
      videoEncoder: encoder.name,
      hardwareType: encoder.hardwareType ?? "software",
    };

    videoPacketStream
      .pipeTo(
        new WritableStream({
          write(packet: ScrcpyMediaStreamPacket) {
            switch (packet.type) {
              case "configuration":
                sharedConfiguration = packet;
                broadcastForPhase(wsStreamingClients, StreamingPhase.METADATA, {
                  type: WSMessageType.CONFIGURATION,
                  metadata: {},
                  data: packet.data,
                });
                break;
              case "data":
                // Handle data packet
                const metadata: DataMetadata = {
                  keyframe: packet.keyframe,
                  pts: packet.pts ? packet.pts.toString() : null,
                };
                broadcastForPhase(wsStreamingClients, StreamingPhase.RENDER, {
                  type: WSMessageType.DATA,
                  metadata: metadata,
                  data: packet.data,
                });
                break;
            }
          },
        }),
      )
      .catch(e => {
        Logger.error(e);
      });
  }

  // to stop the server
  //await scrcpyClient.close()
};

const setupWs = async (httpServer: HTTPServer) => {
  const features = ManagerSingleton.getInstance().getConfig().features;
  const fridaType = features.fridaType;

  const wssStreaming = new WebSocketServer({ noServer: true });
  const wssTerminal = new WebSocketServer({ noServer: true });
  const wssFrida = new WebSocketServer({ noServer: true });

  const wsStreamingClients = ManagerSingleton.getInstance().wsStreamingClients;
  const wsTerminalSessions = ManagerSingleton.getInstance().wsTerminalSessions;
  const wsFridaSessions = ManagerSingleton.getInstance().wsFridaSessions;

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

    if (sharedVideoMetadata) {
      sendStructuredMessage(ws, WSMessageType.STREAM_METADATA, sharedVideoMetadata);
    }

    ws.on("message", (clientMessage: any) => {
      let message = clientMessage.toString();
      const currentClientData = wsStreamingClients.get(id) as WebsocketClient;
      switch (message) {
        case WSMessageType.STREAM_METADATA_ACK:
          wsStreamingClients.set(id, { ...(currentClientData as WebsocketClient), state: StreamingPhase.METADATA });
          if (sharedConfiguration) {
            sendStructuredMessage(ws, WSMessageType.CONFIGURATION, {}, sharedConfiguration.data);
          }
          break;
        case WSMessageType.CONFIGURATION_ACK:
          const nextState: StreamingPhase =
            sharedVideoMetadata?.hardwareType === "hardware" ? StreamingPhase.KEYFRAME : StreamingPhase.RENDER;
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
};

const setupFrida = async () => {
  Logger.info("Downloading Frida Server for the attached device");
  const singleton = ManagerSingleton.getInstance();
  const adb = await singleton.getAdb();
  const fridaVersion = await getFridaVersion();
  const abi = (await adb.subprocess.noneProtocol.spawnWaitText("getprop ro.product.cpu.abi")).trim();
  const arch = mapAbiToFridaArch(abi);

  const fridaServerPath = await downloadFridaServer(fridaVersion, arch, resourcesDir());
  Logger.info(`Frida server downloaded at ${fridaServerPath}`);

  // Push the frida-server
  const sync = await adb.sync();
  const fridaServerDevicePath = path.resolve(DEFAULT_UPLOAD_FOLDER, RESOURCES.FRIDA_SERVER);
  try {
    const fridaFile = resourceFile(RESOURCES.FRIDA_SERVER);
    if (!safeFileExists(fridaFile)) {
      throw new Error("Frida Server file is missing");
    }

    const fridaBuffer: Buffer = await fs.readFile(fridaFile);
    await sync.write({
      filename: fridaServerDevicePath,
      file: new ReadableStream({
        start(controller) {
          controller.enqueue(new Uint8Array(fridaBuffer));
          controller.close();
        },
      }),
      permission: 0o755, // Executable
    });
  } catch (e) {
    Logger.error("Error while pushing Frida Server");
    Logger.error(e);
  } finally {
    await sync.dispose();
  }
  // Start frida-server
  await adb.subprocess.noneProtocol.spawnWaitText("killall frida-server");
  adb.subprocess.noneProtocol.spawn(`su -c '${fridaServerDevicePath}'`);
  Logger.info("Frida server started");
};

export const serverApp = async (app: ExpressApplication, httpServer: HTTPServer) => {
  checkResources();
  const manager = ManagerSingleton.getInstance();

  await manager.init();
  // A device is needed, otherwise there's nothing to do here
  await manager.setAdb();
  if (manager.getConfig().features.fridaEnabled) {
    await setupFrida();
  }

  await setupApi(app);
  await setupWs(httpServer);
  await setupScrcpy();
};
