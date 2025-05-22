import { WebSocketServer, WebSocket } from "ws";
import { Adb, decodeUtf8, encodeUtf8 } from "@yume-chan/adb";
import { ManagerSingleton } from "@server/manager";
import Logger from "@server/utils/logger";

export const setupTerminalWss = (wssTerminal: WebSocketServer) => {
  const singleton = ManagerSingleton.getInstance();
  const wsTerminalSessions = singleton.wsTerminalSessions;

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
};
