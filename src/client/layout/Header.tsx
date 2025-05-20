import { useState } from "react";
import { useLocation, useNavigate } from "@tanstack/react-router";
import { motion } from "motion/react";
import Logo from "@client/assets/logo.png";
import { PAGES } from "@client/config";

interface INavItem {
  label: string;
  to: string;
  routeEnabled: boolean;
}

const fridaRouteEnabled = !(import.meta.env.DROIDGROUND_FRIDA_DISABLED === "true");
const fileBrowserRouteEnabled = !(import.meta.env.DROIDGROUND_FILE_BROWSER_DISABLED === "true");
const appManagerRouteEnabled = !(import.meta.env.DROIDGROUND_APP_MANAGER_DISABLED === "true");
const terminalRouteEnabled = !(import.meta.env.DROIDGROUND_TERMINAL_DISABLED === "true");
const logsRouteEnabled = !(import.meta.env.DROIDGROUND_LOGCAT_DISABLED === "true");

const navItems: INavItem[] = [
  { label: "Overview", to: PAGES.OVERVIEW, routeEnabled: true },
  { label: "Frida", to: PAGES.FRIDA, routeEnabled: fridaRouteEnabled },
  { label: "File Browser", to: PAGES.FILE_BROWSER, routeEnabled: fileBrowserRouteEnabled },
  { label: "App Manager", to: PAGES.APP_MANAGER, routeEnabled: appManagerRouteEnabled },
  { label: "Terminal", to: PAGES.TERMINAL, routeEnabled: terminalRouteEnabled },
  { label: "Logs", to: PAGES.LOGS, routeEnabled: logsRouteEnabled },
];

const Navbar: React.FC = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const [hovered, setHovered] = useState<INavItem | null>(null);

  return (
    <nav className="px-2 py-1">
      <ul className="relative flex space-x-8 text-sm font-medium">
        {navItems
          .filter(i => i.routeEnabled)
          .map(item => (
            <li
              key={item.to}
              className="relative m-0 px-2 cursor-pointer"
              onMouseEnter={() => setHovered(item)}
              onMouseLeave={() => setHovered(null)}
            >
              {hovered === item && (
                <motion.div
                  layoutId="hover-bg"
                  className="absolute inset-0 bg-gray-800 rounded-md z-0"
                  transition={{ type: "spring", stiffness: 500, damping: 30 }}
                />
              )}
              <button
                onClick={() => navigate(item)}
                className="cursor-pointer relative z-10 px-3 py-2 rounded-md transition-colors text-gray-300"
              >
                {item.label}
                {location.pathname === item.to && (
                  <motion.div
                    layoutId="underline"
                    className="absolute bottom-[-18px] left-0 right-0 h-0.5 bg-info rounded z-20"
                    transition={{ type: "spring", stiffness: 500, damping: 30 }}
                  />
                )}
              </button>
            </li>
          ))}
      </ul>
    </nav>
  );
};

export const Header: React.FC = () => {
  return (
    <header className="w-full bg-neutral h-18 select-none">
      <div className="container m-auto h-full flex items-center justify-between">
        <div className="flex items-center gap-2">
          <img src={Logo} className="h-10" />
          <h1 className="font-orbitron text-2xl select-none">DroidGround</h1>
        </div>
        <Navbar />
      </div>
    </header>
  );
};
