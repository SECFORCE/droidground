import fs from "fs/promises";

// '@yume-chan' imports
import { Adb } from "@yume-chan/adb";
import { DefaultServerPath, ScrcpyCodecOptions, ScrcpyMediaStreamPacket } from "@yume-chan/scrcpy";
import { AdbScrcpyClient, AdbScrcpyOptions3_1 } from "@yume-chan/adb-scrcpy";
import { ReadableStream, WritableStream } from "@yume-chan/stream-extra";
import { TinyH264Decoder } from "@yume-chan/scrcpy-decoder-tinyh264";

// Local imports
import { ManagerSingleton } from "@server/manager";
import { DataMetadata, StreamingPhase, WSMessageType } from "@shared/types";
import Logger from "@server/utils/logger";
import { broadcastForPhase } from "@server/utils/ws";
import { resourceFile } from "@server/utils/helpers";
import { RESOURCES } from "@server/config";

const H264Capabilities = TinyH264Decoder.capabilities.h264;

export const setupScrcpy = async () => {
  const singleton = ManagerSingleton.getInstance();
  const scrcpyFile = resourceFile(RESOURCES.SCRCPY_SERVER);
  const serverBuffer: Buffer = await fs.readFile(scrcpyFile);
  const adb: Adb = await singleton.getAdb();
  const wsStreamingClients = singleton.wsStreamingClients;

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
    singleton.sharedVideoMetadata = {
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
                singleton.sharedConfiguration = packet;
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

  singleton.setScrcpyClient(scrcpyClient);
};
