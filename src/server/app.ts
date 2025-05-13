
import fs from "fs/promises";
import { v4 as uuidv4 } from 'uuid';
import { Server as HTTPServer } from 'http'
import express from 'express';
import {Application as ExpressApplication} from 'express'
import cors from 'cors';
import { WebSocketServer, WebSocket } from 'ws';
import '@dotenvx/dotenvx/config'
import frida, { FileDescriptor, ProcessID } from "frida";

// '@yume-chan' imports
import { BIN } from "@yume-chan/fetch-scrcpy-server";
import { Adb, decodeUtf8, encodeUtf8 } from "@yume-chan/adb";
import { DefaultServerPath, ScrcpyCodecOptions, ScrcpyMediaStreamConfigurationPacket, ScrcpyMediaStreamPacket } from "@yume-chan/scrcpy";
import { AdbScrcpyClient, AdbScrcpyOptions3_1 } from "@yume-chan/adb-scrcpy";
import { ReadableStream, WritableStream } from "@yume-chan/stream-extra";
import { TinyH264Decoder } from "@yume-chan/scrcpy-decoder-tinyh264";

// Local imports
import { ManagerSingleton } from '@server/manager';
import api from '@server/api';
import { DataMetadata, FridaState, StreamingPhase, StreamMetadata, WSMessageType } from "@shared/types";

// Local imports
import Logger from '@server/utils/logger';
import { WebsocketClient } from "@server/utils/types";
import { broadcastForPhase, sendStructuredMessage } from "@server/utils/ws";


const H264Capabilities = TinyH264Decoder.capabilities.h264;

let sharedVideoMetadata: StreamMetadata | null = null;
let sharedConfiguration: ScrcpyMediaStreamConfigurationPacket | null = null;;

const setupApi = async (app: ExpressApplication) => {
  app.use(
    cors({
      exposedHeaders: ['Content-Disposition'],
    }),
  );
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  // Load routes
  app.use('/api/v1', api());
};

const setupScrcpy = async () => {
  const serverBuffer: Buffer = await fs.readFile(BIN);
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

  const encoders = await AdbScrcpyClient.getEncoders(adb, DefaultServerPath,             
    new AdbScrcpyOptions3_1({
      listEncoders: true,
      cleanup: false
    })
  )

  Logger.debug("Listing encoders (and using the first one)")
  Logger.debug(encoders)

  // Choose first encoder for now
  const encoder = encoders.filter(e => e.type === 'video')[0]      
  const scrcpyClient = await AdbScrcpyClient.start(
    adb,
    DefaultServerPath,
    new AdbScrcpyOptions3_1({
      audio: false,
      control: false,
      videoCodec: 'h264',
      videoBitRate: 10000000,
      videoEncoder: encoder.name,
      videoCodecOptions: new ScrcpyCodecOptions({
        iFrameInterval: 1,
        intraRefreshPeriod: 1,
        profile: H264Capabilities.maxProfile,
        level: H264Capabilities.maxLevel,
      })
    }),
  );
          
  // Print output of Scrcpy server
  void scrcpyClient.output.pipeTo(
    new WritableStream<string>({
      write(chunk) {
        Logger.debug("Printing Scrcpy output")
        Logger.debug(chunk);
      },
    }),
  );

  if (scrcpyClient.videoStream) {
    const { metadata: videoMetadata, stream: videoPacketStream } = await scrcpyClient.videoStream;
    sharedVideoMetadata = {...videoMetadata, videoEncoder: encoder.name, hardwareType: encoder.hardwareType ?? "software"};

    videoPacketStream
      .pipeTo(
        new WritableStream({
          write(packet: ScrcpyMediaStreamPacket) {
            switch (packet.type) {
              case "configuration":
                sharedConfiguration = packet
                broadcastForPhase(
                  wsStreamingClients, 
                  StreamingPhase.METADATA, 
                  {
                    type: WSMessageType.CONFIGURATION, 
                    metadata: {}, 
                    data: packet.data
                  }
                )
                break;
              case "data":
                // Handle data packet
                const metadata: DataMetadata = { keyframe: packet.keyframe, pts: packet.pts ? packet.pts.toString() : null };
                broadcastForPhase(
                  wsStreamingClients, 
                  StreamingPhase.RENDER, 
                  {
                    type: WSMessageType.DATA, 
                    metadata: metadata, 
                    data: packet.data
                  }
                )
                break;
            }
          },
        }),
      )
      .catch((e) => {
        Logger.error(e);
    });
  }

  // to stop the server
  //await scrcpyClient.close()
}

const setupWs = async (httpServer: HTTPServer) => {
  const features = ManagerSingleton.getInstance().getConfig().features;

  const wssStreaming = new WebSocketServer({ noServer: true });
  const wssTerminal = new WebSocketServer({ noServer: true });
  const wssFrida = new WebSocketServer({ noServer: true });

  const wsStreamingClients = ManagerSingleton.getInstance().wsStreamingClients;
  const wsTerminalSessions = ManagerSingleton.getInstance().wsTerminalSessions;
  const wsFridaSessions: Map<WebSocket, FridaState | null> =  new Map<WebSocket, FridaState | null>();

  // Handle upgrade requests
  httpServer.on('upgrade', (request, socket, head) => {
    const pathname = new URL(`http://localhost${request.url}`).pathname

    if (pathname === '/streaming') {
      wssStreaming.handleUpgrade(request, socket, head, (ws) => {
        wssStreaming.emit('connection', ws, request);
      });
    } else if (pathname === '/terminal' && features.terminalEnabled) {
      wssTerminal.handleUpgrade(request, socket, head, (ws) => {
        wssTerminal.emit('connection', ws, request);
      });
    } else if (pathname === '/frida' && features.fridaEnabled) {
      wssFrida.handleUpgrade(request, socket, head, (ws) => {
        wssFrida.emit('connection', ws, request);
      });
    } else {
      socket.destroy();
    }
  });

  wssFrida.on('connection', (ws: WebSocket) => {
    ws.once('message', async (msg) => {
      try {
        const onOutput = (pid: ProcessID, fd: FileDescriptor, data: Buffer) => {
          if (pid !== wsFridaSessions.get(ws)?.pid)
              return;

          let description: string;
          if (data.length > 0) {
              description = "\"" + data.toString().replace(/\n/g, "\\n") + "\"";
          } else {
              description = "<EOF>";
          }
          Logger.info(`onOutput(pid=${pid}, fd=${fd}, data=${description})`);
        }

        const onDetached = (reason: frida.SessionDetachReason) => {
          Logger.info(`onDetached(reason="${reason}")`);
          wsFridaSessions.get(ws)?.device?.output.disconnect(onOutput);
          ws.close();
        }

        const onMessage = (m: frida.Message, data: Buffer | null) => {
          const message = m as frida.SendMessage;
          Logger.info("Frida message:", message.payload, "data:", data);
          ws.send(message.payload)
        }
        
        const scriptContent = msg.toString()

        const device = await frida.getUsbDevice();

        wsFridaSessions.set(ws, { device: device, pid: null, script: null });

        device.output.connect(onOutput);

        const droidGroundConfig = ManagerSingleton.getInstance().getConfig()

        const pid = await device.spawn(droidGroundConfig.packageName)
        const session = await device.attach(pid);
        wsFridaSessions.set(ws, { device: device, pid: pid, script: null });

        session.detached.connect(onDetached);
        const script = await session.createScript(scriptContent);
        wsFridaSessions.set(ws, { device: device, pid: pid, script: script });
        script.message.connect(onMessage);

        await script.load();
    
        Logger.info(`Resuming (${pid})`);
        await device.resume(pid);
      } catch (err) {
        ws.send(`An error occurred while running Frida script`);
      }
    })

    ws.on('close', async () => {
      Logger.info('Client disconnected');
      await wsFridaSessions.get(ws)?.script?.unload()
      wsFridaSessions.delete(ws);
    })
  })

  wssTerminal.on('connection', async (ws: WebSocket) => {
    try {
        // 1. Get ADB device
        const adb: Adb = await ManagerSingleton.getInstance().getAdb();

        // 2. Create PTY shell
        const ptyProcess = await adb.subprocess.shellProtocol!.pty();

        void ptyProcess.exited.then(exitCode => {
          Logger.debug(`PTY process exited with code ${exitCode}`)
          wsTerminalSessions.delete(ws);
          ws.send('[Process exited]')
          ws.close()
        }).catch(() => {
          Logger.debug("PTY process killed")
        })

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
        ws.on('message', async (msg) => {
              await writer.write(encodeUtf8(msg.toString()));
        });

        // 5. Cleanup
        ws.on('close', async () => {
            Logger.info('Client disconnected');
            wsTerminalSessions.delete(ws);
            await ptyProcess.kill();
        });
    } catch (err) {
        Logger.error('Error initializing session:', err);
        ws.send(`Error: ${err}`);
        ws.close();
    }
  })

  wssStreaming.on('connection', (ws: WebSocket) => {
    const id = uuidv4();
    wsStreamingClients.set(id, {
      state: StreamingPhase.INIT,
      ws: ws
    })

    Logger.info(`WebSocket Streaming client connected with id '${id}', sending Metadata message (if available)`);
    
    if (sharedVideoMetadata) {
      sendStructuredMessage(ws, WSMessageType.STREAM_METADATA, sharedVideoMetadata)
    }
  
    ws.on('message', (clientMessage: any) => {
      let message = clientMessage.toString()
      const currentClientData = wsStreamingClients.get(id) as WebsocketClient;
      switch (message) {
        case WSMessageType.STREAM_METADATA_ACK:
          wsStreamingClients.set(id, {...currentClientData as WebsocketClient, state: StreamingPhase.METADATA})
          if (sharedConfiguration) {
            sendStructuredMessage(ws, WSMessageType.CONFIGURATION, {}, sharedConfiguration.data)
          }
          break
        case WSMessageType.CONFIGURATION_ACK:
          const nextState: StreamingPhase = sharedVideoMetadata?.hardwareType === 'hardware' ? StreamingPhase.KEYFRAME : StreamingPhase.RENDER;
          wsStreamingClients.set(id, {...currentClientData as WebsocketClient, state: nextState})
          break
        default:
          Logger.error('Unknown message type:', message);
          break
      }
    });
  
    ws.on('close', () => {
      wsStreamingClients.delete(id);
      Logger.info(`WebSocket client with id '${id}' disconnected`);
    });
  });
}

export const serverApp = async (app: ExpressApplication, httpServer: HTTPServer) => {
  const manager = ManagerSingleton.getInstance();

  await manager.init()
  // A device is needed, otherwise there's nothing to do here
  await manager.setAdb();
  await setupApi(app);
  await setupWs(httpServer);
  await setupScrcpy();
}