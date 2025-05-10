
import fs from "fs/promises";
import { v4 as uuidv4 } from 'uuid';
import { Server as HTTPServer } from 'http'
import express from 'express';
import {Application as ExpressApplication} from 'express'
import cors from 'cors';
import { WebSocketServer, WebSocket } from 'ws';
import '@dotenvx/dotenvx/config'

// '@yume-chan' imports
import { BIN } from "@yume-chan/fetch-scrcpy-server";
import { Adb } from "@yume-chan/adb";
import { DefaultServerPath, ScrcpyCodecOptions, ScrcpyMediaStreamConfigurationPacket, ScrcpyMediaStreamPacket } from "@yume-chan/scrcpy";
import { AdbScrcpyClient, AdbScrcpyOptions3_1 } from "@yume-chan/adb-scrcpy";
import { ReadableStream, WritableStream } from "@yume-chan/stream-extra";
import { TinyH264Decoder } from "@yume-chan/scrcpy-decoder-tinyh264";

// Local imports
import { ManagerSingleton } from '@server/manager';
import api from '@server/api';
import { DataMetadata, StreamingPhase, StreamMetadata, WSMessage, WSMessageType, WSMetadata } from "@shared/types";


// Local imports
import Logger from '@server/utils/logger';

interface WebsocketClient {
  state: StreamingPhase
  ws: WebSocket
}

const H264Capabilities = TinyH264Decoder.capabilities.h264;

let sharedVideoMetadata: StreamMetadata | null = null;
let sharedConfiguration: ScrcpyMediaStreamConfigurationPacket | null = null;;

const sendStructuredMessage = (
  ws: WebSocket,
  type: WSMessageType,
  metadata: WSMetadata,
  binaryData?: Uint8Array
) => {
  const typedMetadata = {
    ...metadata,
    type
  }
  const metaBuf = new TextEncoder().encode(JSON.stringify(typedMetadata));
  const metaLenBuf = new Uint8Array(4);
  new DataView(metaLenBuf.buffer).setUint32(0, metaBuf.length);

  const totalLength = 4 + metaBuf.length + (binaryData?.length || 0);
  const fullPayload = new Uint8Array(totalLength);

  fullPayload.set(metaLenBuf, 0);
  fullPayload.set(metaBuf, 4);
  if (binaryData) {
    fullPayload.set(binaryData, 4 + metaBuf.length);
  }

  ws.send(fullPayload);
}

const broadcastForPhase = (websocketClients: Map<string, WebsocketClient>, state: StreamingPhase, message: WSMessage) => {
  for (const [wsClientId, client] of websocketClients) {
    // To avoid issues always send a keyframe first
    if (state === StreamingPhase.RENDER && client.state === StreamingPhase.KEYFRAME) {
      const metadata = message.metadata as DataMetadata;
      if (metadata.keyframe) {
        sendStructuredMessage(client.ws, WSMessageType.DATA, message.metadata, message.data);
        websocketClients.set(wsClientId, {...client, state: StreamingPhase.RENDER})
      }
    } else if (client.state === state) {
      sendStructuredMessage(client.ws, WSMessageType.DATA, message.metadata, message.data);
    }
  }
}

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

const setupWs = async (httpServer: HTTPServer) => {
  const wss = new WebSocketServer({ server: httpServer });
  const websocketClients = new Map<string, WebsocketClient>();

  wss.on('connection', (ws: WebSocket) => {
    const id = uuidv4()
    websocketClients.set(id, {
      state: StreamingPhase.INIT,
      ws: ws
    })

    Logger.info(`WebSocket client connected with id '${id}', sending Metadata message (if available)`);
    
    if (sharedVideoMetadata) {
      sendStructuredMessage(ws, WSMessageType.STREAM_METADATA, sharedVideoMetadata)
    }
  
    ws.on('message', (clientMessage: any) => {
      let message = clientMessage.toString()
      const currentClientData = websocketClients.get(id) as WebsocketClient;
      switch (message) {
        case WSMessageType.STREAM_METADATA_ACK:
          websocketClients.set(id, {...currentClientData as WebsocketClient, state: StreamingPhase.METADATA})
          if (sharedConfiguration) {
            sendStructuredMessage(ws, WSMessageType.CONFIGURATION, {}, sharedConfiguration.data)
          }
          break
        case WSMessageType.CONFIGURATION_ACK:
          const nextState: StreamingPhase = sharedVideoMetadata?.hardwareType === 'hardware' ? StreamingPhase.KEYFRAME : StreamingPhase.RENDER;
          websocketClients.set(id, {...currentClientData as WebsocketClient, state: nextState})
          break
        default:
          Logger.error('Unknown message type:', message);
          break
      }
    });
  
    ws.on('close', () => {
      websocketClients.delete(id);
      Logger.info(`WebSocket client with id '${id}' disconnected`);
    });
  });

  const serverBuffer: Buffer = await fs.readFile(BIN);
  const adb: Adb = await ManagerSingleton.getInstance().getAdb();

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
                  websocketClients, 
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
                  websocketClients, 
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

export const serverApp = async (app: ExpressApplication, httpServer: HTTPServer) => {
  const manager = ManagerSingleton.getInstance();

  await manager.init()
  // A device is needed, otherwise there's nothing to do here
  await manager.setAdb();
  setupApi(app);
  setupWs(httpServer);
}