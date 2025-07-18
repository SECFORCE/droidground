import "dotenv/config";
import { Request, Response } from "express";
import fs from "fs";
import path, { dirname } from "path";
import express from "express";
import http from "http";
import { createServer as createViteServer } from "vite";
import compression from "compression";
import serveStatic from "serve-static";
import { fileURLToPath } from "url";

// Local imports
import { serverApp } from "@server/app";
import Logger from "@shared/logger.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const isTest = process.env.NODE_ENV === "test" || !!process.env.VITE_TEST_BUILD;

const ssrLoader = async (app: express.Application, isProd: boolean) => {
  const root = __dirname;
  const resolve = (p: string) => path.resolve(__dirname, p);

  const indexProd = isProd ? fs.readFileSync(resolve("client/index.html"), "utf-8") : "";

  const requestHandler = express.static(resolve("assets"));

  app.use(requestHandler);
  app.use("/assets", requestHandler);

  /**
   * @type {import('vite').ViteDevServer}
   */
  let vite: any;
  if (!isProd) {
    vite = await createViteServer({
      root,
      logLevel: isTest ? "error" : "info",
      server: {
        middlewareMode: true,
        watch: {
          // During tests we edit the files too fast and sometimes chokidar
          // misses change events, so enforce polling for consistency
          usePolling: true,
          interval: 100,
        },
      },
      appType: "custom",
    });
    // use vite's connect instance as middleware
    app.use(vite.middlewares);
  } else {
    app.use(compression());
    app.use(
      serveStatic(resolve("dist/client"), {
        index: false,
      }),
    );
  }

  app.use("*all", async (req: Request, res: Response) => {
    try {
      const url = req.originalUrl;

      let template, render;
      if (!isProd) {
        // always read fresh template in dev
        template = fs.readFileSync(resolve("index.html"), "utf-8");
        template = await vite.transformIndexHtml(url, template);
        render = (await vite.ssrLoadModule("/src/client/entry-server.tsx")).render;
      } else {
        template = indexProd;
        // Production: dynamically import entry-server.js, ignore TypeScript checking
        // @ts-ignore
        const entryServer = await import("./server/entry-server.js");
        render = entryServer.render;
      }

      const context = {};
      const appHtml = render(url, context);

      const html = template.replace(`<!--root-html-->`, appHtml);

      res.status(200).set({ "Content-Type": "text/html" }).end(html);
    } catch (e: any) {
      !isProd && vite.ssrFixStacktrace(e);
      Logger.error(e.stack);
      res.status(500).end(e.stack);
    }
  });
};

const createServer = async (isProd = process.env.NODE_ENV === "production") => {
  const app = express();
  const httpServer = http.createServer(app);
  await serverApp(app, httpServer);
  await ssrLoader(app, isProd);

  const host = process.env.DROIDGROUND_HOST || "0.0.0.0";
  const port = process.env.DROIDGROUND_PORT || 4242;
  httpServer.listen(Number(port), host, () => {
    Logger.info(`DroidGround is running on http://${host}:${port} in ${isProd ? "production" : "development"} mode.`);
  });
};

createServer();
