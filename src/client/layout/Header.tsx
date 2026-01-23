import { useEffect, useMemo, useRef, useState } from "react";
import { useLocation, useNavigate } from "@tanstack/react-router";
import { motion } from "motion/react";
import toast from "react-hot-toast";
import Logo from "@client/assets/logo.png";
import { PAGES } from "@client/config";
import { RESTManagerInstance } from "@client/api/rest";
import { WEBSOCKET_ENDPOINTS } from "@shared/endpoints";
import { JobInfo, JobStatusType } from "@shared/types";
import { ConfirmModal } from "@client/components";
import { useAPI } from "@client/context/API";
import { BsGithub } from "react-icons/bs";
import { HiQueueList } from "react-icons/hi2";
import { CiStopwatch } from "react-icons/ci";
import { PiEmptyDuotone } from "react-icons/pi";
import { LuMenu } from "react-icons/lu";

interface INavItem {
  label: string;
  to: string;
  routeEnabled: boolean;
}

const statusMappings = {
  waiting: 0,
  running: 1,
  completed: 2,
};
const isJobStatusNewer = (statusA: JobStatusType, statusB: JobStatusType) => {
  return statusMappings[statusA] > statusMappings[statusB];
};

const Navbar: React.FC = () => {
  const { featuresConfig } = useAPI();
  const location = useLocation();
  const navigate = useNavigate();
  const [hovered, setHovered] = useState<string | null>(null);
  const resetCtfDialogRef = useRef<HTMLDialogElement | null>(null);
  const [queueStatus, setQueueStatus] = useState<JobInfo[]>([]);

  if (!featuresConfig) {
    return <></>;
  }

  // Routes
  const { fridaEnabled, fileBrowserEnabled, appManagerEnabled, terminalEnabled, logcatEnabled, teamModeEnabled } =
    featuresConfig;

  const navItems: INavItem[] = [
    { label: "Overview", to: PAGES.OVERVIEW, routeEnabled: true },
    { label: "Frida", to: PAGES.FRIDA, routeEnabled: fridaEnabled },
    { label: "File Browser", to: PAGES.FILE_BROWSER, routeEnabled: fileBrowserEnabled },
    { label: "App Manager", to: PAGES.APP_MANAGER, routeEnabled: appManagerEnabled },
    { label: "Terminal", to: PAGES.TERMINAL, routeEnabled: terminalEnabled },
    { label: "Logs", to: PAGES.LOGS, routeEnabled: logcatEnabled },
    { label: "Exploit Server", to: PAGES.EXPLOIT_SERVER, routeEnabled: teamModeEnabled },
  ];

  const suffix = useMemo(() => {
    const suffix = featuresConfig.basePath.length > 0 ? featuresConfig.basePath : "";
    return suffix;
  }, [featuresConfig]);

  useEffect(() => {
    if (!appManagerEnabled) {
      return;
    }

    const isHttps = typeof window !== "undefined" && window.location.protocol === "https:";
    const prefix = isHttps ? "wss" : "ws";
    const wsBaseUrl = `${prefix}://${window.location.host}${suffix}`;
    const socket = new WebSocket(`${wsBaseUrl}${WEBSOCKET_ENDPOINTS.NOTIFICATIONS}`);

    // When data comes from backend, write to terminal
    socket.addEventListener("message", event => {
      const jobs: JobInfo[] = JSON.parse(event.data);
      setQueueStatus(prevQueueStatus => {
        let jobMappings: { [id: string]: JobInfo } = prevQueueStatus.reduce((prev, curr) => {
          return { ...prev, [curr.id]: curr };
        }, {});

        for (const j of jobs) {
          if (!jobMappings[j.id] || isJobStatusNewer(j.status, jobMappings[j.id].status)) {
            jobMappings[j.id] = j;
          }
        }

        return Object.values(jobMappings).filter(j => j.status !== JobStatusType.COMPLETED);
      });

      for (const j of jobs.filter(j => j.status !== JobStatusType.WAITING)) {
        const action = j.status === JobStatusType.RUNNIG ? "started" : "completed";
        toast.success(`Exploit App ${j.packageName} correctly ${action}!`);
      }
    });

    return () => {
      socket.close();
    };
  }, [appManagerEnabled]);

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
        description={
          <>
            This will reset the CTF to its original status (usually it will perform some cleanup and uninstall/reinstall
            the app). <br />
            Are you sure?
          </>
        }
        onConfirm={reset}
      />

      {/********************
       *   Mobile Navbar   *
       **********************/}
      <div className="flex items-center gap-2 lg:hidden">
        <a
          href="https://github.com/SECFORCE/droidground"
          target="_blank"
          rel="noreferrer"
          className="btn btn-ghost btn-sm px-2"
        >
          <BsGithub size={22} className="text-white" />
        </a>

        <div className="dropdown dropdown-end">
          <label tabIndex={0} className="btn btn-ghost btn-sm px-2" aria-label="Open menu">
            <LuMenu size={24} />
          </label>
          <ul
            tabIndex={0}
            className="menu dropdown-content mt-3 w-52 rounded-box bg-base-200 p-2 shadow border border-base-300"
          >
            {navItems
              .filter(i => i.routeEnabled)
              .map(item => (
                <li key={item.to}>
                  <button
                    className="justify-between"
                    onClick={() => {
                      (document.activeElement as HTMLElement | null)?.blur();
                      navigate(item);
                    }}
                  >
                    {item.label}
                  </button>
                </li>
              ))}
          </ul>
        </div>
      </div>

      {/*********************
       *   Desktop Navbar   *
       **********************/}
      <nav className="hidden lg:flex px-2 py-1 h-12 items-center">
        <ul className="relative flex space-x-8 text-sm font-medium">
          {navItems
            .filter(i => i.routeEnabled)
            .map(item => (
              <li
                key={item.to}
                className="relative m-0 px-2 cursor-pointer"
                onMouseEnter={() => {
                  setHovered(item.to);
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
                  {location.pathname === `${suffix}${item.to}` && (
                    <motion.div
                      layoutId="underline"
                      className="absolute -bottom-4.5 left-0 right-0 h-0.5 bg-info rounded z-20"
                      transition={{ type: "spring", stiffness: 500, damping: 30 }}
                    />
                  )}
                </button>
              </li>
            ))}
        </ul>
        {featuresConfig.resetEnabled && (
          <button className="btn btn-error ml-4" onClick={() => resetCtfDialogRef.current?.showModal()}>
            Reset
          </button>
        )}
        <div className="flex h-full items-center justify-center">
          <div className="flex h-6">
            <div className="divider divider-horizontal" />
          </div>
          <div className="flex gap-4">
            {appManagerEnabled && (
              <div className="dropdown dropdown-center">
                <HiQueueList
                  size={24}
                  tabIndex={0}
                  role="button"
                  className="cursor-pointer text-gray-400 group-hover:text-white hover:text-white transition-all duration-300"
                />
                <ul
                  tabIndex={-1}
                  className="dropdown-content bg-base-300 rounded-box z-1 w-80 p-2 mt-4 shadow-sm flex flex-col gap-2"
                >
                  {queueStatus.length === 0 && (
                    <li className="flex items-center gap-4 bg-base-100 rounded-box p-2 text-sm">
                      <PiEmptyDuotone size={24} className="text-error" />
                      <p>Exploit app queue is empty.</p>
                    </li>
                  )}

                  {queueStatus.map(jobStatus => (
                    <li key={jobStatus.id} className="flex items-center gap-4 bg-base-100 rounded-box p-2 text-sm">
                      {jobStatus.status === JobStatusType.RUNNIG ? (
                        <span className="loading loading-spinner text-orange-400" />
                      ) : (
                        <CiStopwatch size={24} className="text-accent" />
                      )}
                      <div>
                        <p>
                          Exploit App '{jobStatus.packageName}'{" "}
                          {jobStatus.status === JobStatusType.RUNNIG ? "running" : "queued"}
                        </p>
                        <span className="text-xs text-gray-400">{new Date(jobStatus.createdAt).toLocaleString()}</span>
                      </div>
                    </li>
                  ))}
                </ul>
              </div>
            )}
            <a href="https://github.com/SECFORCE/droidground" target="_blank" className="group">
              <BsGithub
                size={24}
                className="text-gray-400 group-hover:text-white hover:text-white transition-all duration-300"
              />
            </a>
          </div>
        </div>
      </nav>
    </>
  );
};

export const Header: React.FC = () => {
  return (
    <header className="w-full bg-neutral select-none">
      <div className="container mx-auto h-18 px-4 sm:px-6 lg:px-8">
        <div className="h-full flex items-center justify-between gap-3">
          <div className="flex items-center gap-2 min-w-0">
            <img src={Logo} className="h-10" />
            <h1 className="font-orbitron text-xl sm:text-2xl truncate">DroidGround</h1>
          </div>
          <Navbar />
        </div>
      </div>
    </header>
  );
};
