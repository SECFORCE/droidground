import { useRef, useState } from "react";
import { useLocation, useNavigate } from "@tanstack/react-router";
import { motion } from "motion/react";
import Logo from "@client/assets/logo.png";
import { PAGES } from "@client/config";
import { RESTManagerInstance } from "@client/api/rest";
import toast from "react-hot-toast";
import { ConfirmModal } from "@client/components";
import { useAPI } from "@client/context/API";
import { BsGithub } from "react-icons/bs";

interface INavItem {
  label: string;
  to: string;
  routeEnabled: boolean;
}

const Navbar: React.FC = () => {
  const { featuresConfig } = useAPI();
  const location = useLocation();
  const navigate = useNavigate();
  const [hovered, setHovered] = useState<string | null>(null);
  const resetCtfDialogRef = useRef<HTMLDialogElement | null>(null);

  if (!featuresConfig) {
    return <></>;
  }

  // Routes
  const { fridaEnabled, fileBrowserEnabled, appManagerEnabled, terminalEnabled, logcatEnabled } = featuresConfig;

  const navItems: INavItem[] = [
    { label: "Overview", to: PAGES.OVERVIEW, routeEnabled: true },
    { label: "Frida", to: PAGES.FRIDA, routeEnabled: fridaEnabled },
    { label: "File Browser", to: PAGES.FILE_BROWSER, routeEnabled: fileBrowserEnabled },
    { label: "App Manager", to: PAGES.APP_MANAGER, routeEnabled: appManagerEnabled },
    { label: "Terminal", to: PAGES.TERMINAL, routeEnabled: terminalEnabled },
    { label: "Logs", to: PAGES.LOGS, routeEnabled: logcatEnabled },
  ];

  const reset = async () => {
    try {
      await RESTManagerInstance.resetCtf();
      toast.success("Reset correctly performed");
    } catch (e) {
      console.error(e);
      toast.error("Error while resetting the CTF");
    }
  };

  return (
    <>
      {/*************
       *    Modals   *
       ***************/}

      {/* Start Activity Modal */}
      <ConfirmModal
        dialogRef={resetCtfDialogRef}
        title="Reset CTF"
        description="This will reset the CTF to its original status (usually it will perform some cleanup and uninstall/reinstall the app. Are you sure?"
        onConfirm={reset}
      />

      {/*************
       *   Navbar   *
       ***************/}
      <nav className="flex px-2 py-1 h-12">
        <ul className="relative flex space-x-8 text-sm font-medium">
          {navItems
            .filter(i => i.routeEnabled)
            .map(item => (
              <li
                key={item.to}
                className="relative m-0 px-2 cursor-pointer"
                onMouseEnter={() => {
                  console.log(item), setHovered(item.to);
                }}
                onMouseLeave={() => setHovered(null)}
              >
                {hovered === item.to && (
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
                      className="absolute bottom-[-20px] left-0 right-0 h-0.5 bg-info rounded z-20"
                      transition={{ type: "spring", stiffness: 500, damping: 30 }}
                    />
                  )}
                </button>
              </li>
            ))}
        </ul>
        <button className="btn btn-error ml-4" onClick={() => resetCtfDialogRef.current?.showModal()}>
          Reset
        </button>
        <div className="flex h-full items-center justify-center">
          <div className="flex h-[1.5rem]">
            <div className="divider divider-horizontal" />
          </div>
          <a href="https://github.com/SECFORCE/droidground" target="_blank" className="group">
            <BsGithub
              size={24}
              className="text-gray-400 group-hover:text-white hover:text-white transition-all duration-300"
            />
          </a>
        </div>
      </nav>
    </>
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
