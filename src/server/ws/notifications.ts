import { WebSocketServer, WebSocket } from "ws";
import { ManagerSingleton } from "@server/manager";
import Logger from "@shared/logger";
import { randomUUID } from "crypto";

export const setupNotificationsWss = (wssNotifications: WebSocketServer) => {
  const singleton = ManagerSingleton.getInstance();
  const wsNotificationSessions = singleton.wsNotificationSessions;

  wssNotifications.on("connection", async (ws: WebSocket) => {
    try {
      const id = randomUUID();
      wsNotificationSessions.set(id, ws);
      Logger.debug(`User connected to notifications websocket.`);

      // Send current queue status
      const queueStatus = singleton.queue.getQueueStatus();
      ws.send(JSON.stringify(queueStatus));

      ws.on("close", async () => {
        Logger.info("Notifications client disconnected");
        wsNotificationSessions.delete(id);
      });
    } catch (err) {
      Logger.error(`Error initializing session: ${err}`);
      ws.send(`${err}`);
      ws.close();
    }
  });
};
