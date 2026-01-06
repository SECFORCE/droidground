import { Server as HTTPServer } from "http";
import { WebSocketServer } from "ws";
import { parse } from "url";
import { ManagerSingleton } from "@server/manager";
import { WEBSOCKET_ENDPOINTS } from "@shared/endpoints";
import { setupScrcpyWss } from "@server/ws/scrcpy";
import { setupTerminalWss } from "@server/ws/terminal";
import { setupFridaWss } from "@server/ws/frida";
import { setupExploitTerminalWss } from "@server/ws/exploitServer";

export const setupWs = async (httpServer: HTTPServer, basePath: string) => {
  const singleton = ManagerSingleton.getInstance();
  const features = singleton.getConfig().features;

  const wssScrcpy = new WebSocketServer({ noServer: true });
  const wssTerminal = new WebSocketServer({ noServer: true });
  const wssFrida = new WebSocketServer({ noServer: true });
  const wssExploitServer = new WebSocketServer({ noServer: true });

  // Handle upgrade requests
  httpServer.on("upgrade", (request, socket, head) => {
    const { pathname } = parse(request.url ?? "", true);
    if (pathname === `${basePath}${WEBSOCKET_ENDPOINTS.STREAMING}`) {
      wssScrcpy.handleUpgrade(request, socket, head, ws => {
        wssScrcpy.emit("connection", ws, request);
      });
    } else if (pathname === `${basePath}${WEBSOCKET_ENDPOINTS.TERMINAL}` && features.terminalEnabled) {
      wssTerminal.handleUpgrade(request, socket, head, ws => {
        wssTerminal.emit("connection", ws, request);
      });
    } else if (pathname === `${basePath}${WEBSOCKET_ENDPOINTS.FRIDA}` && features.fridaEnabled) {
      wssFrida.handleUpgrade(request, socket, head, ws => {
        wssFrida.emit("connection", ws, request);
      });
    } else if (pathname === `${basePath}${WEBSOCKET_ENDPOINTS.EXPLOIT_SERVER}` && features.teamModeEnabled) {
      wssExploitServer.handleUpgrade(request, socket, head, ws => {
        wssExploitServer.emit("connection", ws, request);
      });
    } else {
      socket.destroy();
    }
  });

  setupScrcpyWss(wssScrcpy);
  setupTerminalWss(wssTerminal);
  setupFridaWss(wssFrida);
  setupExploitTerminalWss(wssExploitServer);
};
