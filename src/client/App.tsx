import { RouterProvider } from "@tanstack/react-router";
import { createRootRoute, createRoute, createRouter, Outlet } from "@tanstack/react-router";
import { WebSocketProvider } from "@client/context/WebSocket";
import { Header, VideoRenderer } from "@client/layout";
import { Overview, Frida, NotFound, FileBrowser, AppManager, Terminal, Logs } from "@client/views";
import { PAGES } from "@client/config";

const rootRoute = createRootRoute()

const DefaultRoute = () => {
    return (
        <div className="min-h-screen flex flex-col">
        <Header />
        <div className="container m-auto h-full py-4 flex items-start gap-8">
            <VideoRenderer />
            <Outlet />
        </div>
    </div>
    )
}

const ErrorRoute = () => {
    return (
        <div className="min-h-screen flex flex-col">
        <Header />
        <div className="container m-auto h-full py-4 flex items-start gap-8">
            <Outlet />
        </div>
    </div>
    )
}

const defaultRoute = createRoute({
    getParentRoute: () => rootRoute,
    id: 'defaultRoute',
    component: DefaultRoute,
})

const errorRoute = createRoute({
    getParentRoute: () => rootRoute,
    id: 'errorRoute',
    component: ErrorRoute,
})

const indexRoute = createRoute({
    getParentRoute: () => defaultRoute,
    path: PAGES.OVERVIEW,
    component: Overview,
})

const fridaRoute = createRoute({
    getParentRoute: () => defaultRoute,
    path: PAGES.FRIDA,
    component: Frida,
})

const fileBrowserRoute = createRoute({
    getParentRoute: () => defaultRoute,
    path: PAGES.FILE_BROWSER,
    component: FileBrowser,
})
const appManagerRoute = createRoute({
    getParentRoute: () => defaultRoute,
    path: PAGES.APP_MANAGER,
    component: AppManager,
})
const terminalRoute = createRoute({
    getParentRoute: () => defaultRoute,
    path: PAGES.TERMINAL,
    component: Terminal,
})
const logsRoute = createRoute({
    getParentRoute: () => defaultRoute,
    path: PAGES.LOGS,
    component: Logs,
})

const notFoundRoute = createRoute({
    getParentRoute: () => errorRoute,
    path: '*',
    component: NotFound
  });

const routeTree = rootRoute.addChildren([
    defaultRoute.addChildren([indexRoute, fridaRoute, fileBrowserRoute, appManagerRoute, terminalRoute, logsRoute]), 
    errorRoute.addChildren([notFoundRoute])
])

const router = createRouter({ routeTree })

declare module '@tanstack/react-router' {
    interface Register {
        router: typeof router
    }
}

export const App = () => {
    return (
        <WebSocketProvider>
            <RouterProvider router={router} />
        </WebSocketProvider>
    )
}