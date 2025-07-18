/******************************************************
 * This is just an example on how to dynamically
 * spawn multiple instances of DroidGround. In this
 * case Docker is used with Traefik and the
 * 'halimqarroum/docker-android' Docker image for
 * Android. But that's basically up to you and, as
 * you can see, you can easily craft your own spawner.
 ******************************************************/

import "dotenv/config";
import express from "express";
import { exec, spawn } from "child_process";
import { promisify } from "util";
import { Router, RequestHandler, Request, Response, Application as ExpressApplication } from "express";
import { fileURLToPath } from "url";
import path from "path";
import { v4 as uuidv4 } from "uuid";

// Hardcoded values
const PROXY_COMPOSE = "compose.proxy.yaml";
const DROIDGROUND_COMPOSE = "compose.docker-android.yaml";
const SHARED_NETWORK = "droidground";
const MAX_INSTANCES = 2;

const execAsync = promisify(exec);
const endpoint = Router(); // Define an Express Router
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
let currentInstances: string[] = [];

const runCommandLive = (
  command: string,
  args: string[],
  cwd?: string,
  envVars?: Record<string, string>,
): Promise<void> => {
  return new Promise((resolve, reject) => {
    const env = {
      ...process.env, // inherit current process environment
      ...envVars, // override/add specified env vars
    };

    const child = spawn(command, args, {
      cwd,
      env,
      stdio: "inherit", // pipe stdio directly to the terminal
    });

    child.on("error", err => reject(err));
    child.on("close", code => {
      code === 0 ? resolve() : reject(new Error(`Command "${command} ${args.join(" ")}" exited with code ${code}`));
    });
  });
};

const ensureNetwork = async (networkName: string): Promise<void> => {
  try {
    const { stdout } = await execAsync(`docker network ls --filter name=^${networkName}$ --format "{{.Name}}"`);
    const exists = stdout.trim() === networkName;

    if (exists) {
      console.log(`Docker network "${networkName}" already exists.`);
      return;
    }

    console.log(`Creating Docker network "${networkName}"...`);
    await execAsync(`docker network create ${networkName}`);
    console.log(`Docker network "${networkName}" created.`);
  } catch (error) {
    console.error(`Error handling network "${networkName}":`, error);
    throw error;
  }
};

const runComposeProject = async (
  composeFile: string,
  projectName?: string,
  envVars?: Record<string, string>,
): Promise<void> => {
  let args = ["compose", "-f", composeFile];
  if (projectName) {
    args.push(...["-p", projectName]);
  }
  args.push(...["up", "-d"]);

  console.log(`Running docker compose for "${composeFile}"`);
  await runCommandLive("docker", args, __dirname, envVars);
  console.log(`Compose project "${composeFile}" started.`);
};

const destroyComposeProject = async (composeFile: string, projectName?: string): Promise<void> => {
  let args = ["compose", "-f", composeFile];
  if (projectName) {
    args.push(...["-p", projectName]);
  }
  args.push("down");
  console.log(`Stopping docker compose for "${composeFile}"`);
  await runCommandLive("docker", args, __dirname);
  console.log(`Compose project "${composeFile}" stopped.`);
};

class APIController {
  getInstances: RequestHandler = async (_req: Request, res: Response) => {
    res.json({ instances: currentInstances }).end();
  };

  startInstance: RequestHandler = async (_req: Request, res: Response) => {
    if (currentInstances.length >= MAX_INSTANCES) {
      res.status(400).json({ result: "Max number of instances reached" }).end();
      return;
    }

    const id = uuidv4();
    await runComposeProject(DROIDGROUND_COMPOSE, id, { INSTANCE_ID: id });
    currentInstances.push(id);

    res.json({ result: "Instance correctly spawned!", id: id }).end();
  };

  genericError: RequestHandler = async (_req: Request, res: Response) => {
    res.status(400).json({ result: "This feature is either missing or disabled." }).end();
  };
}

const controllerInstance = new APIController();

const routes = (app: Router) => {
  app.use("", endpoint);

  // Cache-control middleware for all routes within this router
  endpoint.use((_req, res, next) => {
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
    next();
  });

  endpoint.get("/instances", controllerInstance.getInstances);
  endpoint.post("/spawn", controllerInstance.startInstance);
  endpoint.all("/*all", controllerInstance.genericError);
};

const api = () => {
  const app: express.Router = express.Router();
  routes(app);
  return app;
};

const setupServer = async (app: ExpressApplication) => {
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  // Load routes
  app.use("/api/v1", api());
  app.get("/", (_req, res) => {
    res.sendFile(path.join(__dirname, "index.html"));
  });
  app.get("/logo.png", (_req, res) => {
    res.sendFile(path.join(__dirname, "logo.png"));
  });
  app.all("/*all", (req, res) => {
    res.redirect("/");
  });
};

const spawnerApp = async (app: ExpressApplication) => {
  await setupServer(app);
};

const cleanup = async () => {
  for (const instance of currentInstances) {
    await destroyComposeProject(DROIDGROUND_COMPOSE, instance);
  }
  await destroyComposeProject(PROXY_COMPOSE);
};

process.on("SIGINT", async () => {
  console.log("SIGINT received. Cleaning up...");
  await cleanup();
  process.exit(0);
});

process.on("SIGTERM", async () => {
  console.log("SIGTERM received. Cleaning up...");
  await cleanup();
  process.exit(0);
});

const createServer = async (isProd = process.env.NODE_ENV === "production") => {
  await ensureNetwork(SHARED_NETWORK);
  await runComposeProject(PROXY_COMPOSE);

  const app = express();
  await spawnerApp(app);

  const host = process.env.DROIDGROUND_HOST || "0.0.0.0";
  const port = process.env.DROIDGROUND_PORT || 4242;
  app.listen(Number(port), host, () => {
    console.log(
      `DroidGround Sample Spawner is running on http://${host}:${port} in ${isProd ? "production" : "development"} mode.`,
    );
  });
};

createServer();
