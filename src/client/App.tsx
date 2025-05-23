import { Suspense, useEffect, useState } from "react";
import { RouterProvider } from "@tanstack/react-router";
import { createRootRoute, createRoute, createRouter, Outlet } from "@tanstack/react-router";
import { WebSocketProvider } from "@client/context/WebSocket";
import { Header, VideoRenderer } from "@client/layout";
import {
  Overview,
  FridaFull,
  FridaJailed,
  NotFound,
  FileBrowser,
  AppManager,
  Terminal,
  Logs,
  Error,
} from "@client/views";
import { PAGES } from "@client/config";
import { APIProvider, useAPI } from "@client/context/API";
import { sleep } from "@shared/helpers";
import Logo from "@client/assets/logo.png";
import { Toaster } from "react-hot-toast";

const rootRoute = createRootRoute();

const loadingMessages = [
  "Placing flag on the device...",
  "Injecting shellcode...",
  "Bypassing ASLR...",
  "Escalating privileges...",
  "Patching kernel live...",
  "Starting reverse shell...",
  "Encrypting payload...",
  "Spoofing MAC address...",
  "Hijacking systemd...",
  "Deploying rootkit...",
];

const AppRoute = () => {
  const { featuresConfig, deviceInfo } = useAPI();
  const [isLoading, setIsLoading] = useState<boolean>(true);

  const [progress, setProgress] = useState(0);
  const [visibleMessages, setVisibleMessages] = useState<string[]>([]);

  const waitAndLoad = async () => {
    await sleep(1500);
    setIsLoading(false);
  };

  useEffect(() => {
    if (featuresConfig && deviceInfo) {
      const totalDuration = 1500; // ms
      const intervalDuration = 10; // update every 10ms
      const totalSteps = totalDuration / intervalDuration;

      let step = 0;
      const interval = setInterval(() => {
        step += 1;
        setProgress(Math.min(100, (step / totalSteps) * 100));
      }, intervalDuration);

      const shuffled = [...loadingMessages].sort(() => 0.5 - Math.random());
      setVisibleMessages([shuffled[0], shuffled[1]]);

      const timeout = setTimeout(() => {
        clearInterval(interval);
      }, totalDuration);

      waitAndLoad();

      return () => {
        clearInterval(interval);
        clearTimeout(timeout);
      };
    }
  }, [featuresConfig, deviceInfo]);

  if (isLoading) {
    return (
      <div className="w-screen h-screen flex flex-col gap-6 items-center justify-center">
        <div className="flex flex-col items-center gap-2">
          <img src={Logo} className="h-16" />
          <h1 className="font-orbitron text-2xl select-none">DroidGround</h1>
        </div>
        <progress className="progress w-96" value={progress} max={100}></progress>
        <p className="text-lg font-mono">{progress < 50 ? visibleMessages[0] : visibleMessages[1]}</p>
      </div>
    );
  }

  return (
    <WebSocketProvider>
      <div className="min-h-screen flex flex-col">
        <Header />
        <div className="container m-auto h-full py-4 flex items-start gap-8">
          <VideoRenderer />
          <Outlet />
        </div>
      </div>
    </WebSocketProvider>
  );
};

const DefaultRoute = () => {
  return (
    <>
      <AppRoute />
      <Toaster position="bottom-right" />
    </>
  );
};

const ErrorComponent = () => {
  return (
    <div className="min-h-screen flex flex-col">
      <Header />
      <div className="container m-auto h-full py-4 flex items-start gap-8">
        <Error />
      </div>
    </div>
  );
};

const NotFoundRoute = () => {
  return (
    <div className="min-h-screen flex flex-col">
      <Header />
      <div className="container m-auto h-full py-4 flex items-start gap-8">
        <Outlet />
      </div>
    </div>
  );
};

const SuspenceTerminal = () => {
  return (
    <Suspense>
      <Terminal />
    </Suspense>
  );
};

const defaultRoute = createRoute({
  getParentRoute: () => rootRoute,
  id: "defaultRoute",
  component: DefaultRoute,
  errorComponent: ErrorComponent,
});

const notFoundRoute = createRoute({
  getParentRoute: () => rootRoute,
  id: "errorRoute",
  component: NotFoundRoute,
});

const indexRoute = createRoute({
  getParentRoute: () => defaultRoute,
  path: PAGES.OVERVIEW,
  component: Overview,
});

const fridaFullRoute = createRoute({
  getParentRoute: () => defaultRoute,
  path: PAGES.FRIDA,
  component: FridaFull,
});

const fridaJailedRoute = createRoute({
  getParentRoute: () => defaultRoute,
  path: PAGES.FRIDA,
  component: FridaJailed,
});

const fileBrowserRoute = createRoute({
  getParentRoute: () => defaultRoute,
  path: PAGES.FILE_BROWSER,
  component: FileBrowser,
});
const appManagerRoute = createRoute({
  getParentRoute: () => defaultRoute,
  path: PAGES.APP_MANAGER,
  component: AppManager,
});
const terminalRoute = createRoute({
  getParentRoute: () => defaultRoute,
  path: PAGES.TERMINAL,
  component: SuspenceTerminal,
});
const logsRoute = createRoute({
  getParentRoute: () => defaultRoute,
  path: PAGES.LOGS,
  component: Logs,
});

const catchAllRoute = createRoute({
  getParentRoute: () => notFoundRoute,
  path: "*",
  component: NotFound,
});

const Main = () => {
  const { featuresConfig, deviceInfo } = useAPI();

  if (!featuresConfig || !deviceInfo) {
    return <></>;
  }

  const { appManagerEnabled, terminalEnabled, fileBrowserEnabled, fridaEnabled, logcatEnabled, fridaType } =
    featuresConfig;

  // Determine the correct Frida route to use. Default value is FridaJailed
  const fridaRoute = fridaType === "full" ? fridaFullRoute : fridaJailedRoute;

  const allRoutes = [indexRoute, fridaRoute, fileBrowserRoute, appManagerRoute, terminalRoute, logsRoute];
  const routesEnabled = [true, fridaEnabled, fileBrowserEnabled, appManagerEnabled, terminalEnabled, logcatEnabled];

  if (allRoutes.length !== routesEnabled.length) {
    throw Error("Length mismatch!");
  }

  const enabledRoutes = allRoutes.filter((_, index) => routesEnabled[index]);

  const routeTree = rootRoute.addChildren([
    defaultRoute.addChildren(enabledRoutes),
    notFoundRoute.addChildren([catchAllRoute]),
  ]);

  const router = createRouter({ routeTree });

  return <RouterProvider router={router} />;
};

declare module "@tanstack/react-router" {
  interface Register {
    router: ReturnType<typeof createRouter>;
  }
}

export const App = () => {
  return (
    <APIProvider>
      <Main />
    </APIProvider>
  );
};
