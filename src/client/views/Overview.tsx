import { useEffect, useRef, useState } from "react";
import toast from "react-hot-toast";

import { IoInformationCircleOutline, IoLogoAndroid } from "react-icons/io5";
import { TbCpu, TbVersions } from "react-icons/tb";
import { MdSpaceDashboard } from "react-icons/md";
import { RESTManagerInstance } from "@client/api/rest";
import { BugreportzStatusResponse } from "@shared/api";
import { useAPI } from "@client/context/API";
import { StartActivityModal, StartBroadcastModal, StartServiceModal } from "@client/components";

export const Overview: React.FC = () => {
  const { featuresConfig, deviceInfo } = useAPI();
  const [bugreportStatus, setBugreportStatus] = useState<BugreportzStatusResponse>({
    isBugreportAvailable: false,
    isRunning: false,
  });
  const isPowerMenuEnabled = featuresConfig.shutdownEnabled || featuresConfig.rebootEnabled;
  // Dialogs
  const startActivityDialogRef = useRef<HTMLDialogElement | null>(null);
  const startBroadcastReceiverDialogRef = useRef<HTMLDialogElement | null>(null);
  const startServiceDialogRef = useRef<HTMLDialogElement | null>(null);

  const getBugreportzStatus = async () => {
    try {
      const res = await RESTManagerInstance.getBugreportzStatus();
      setBugreportStatus(res.data);
    } catch (e) {
      console.error(e);
      toast.error("Error while starting bugreportz.");
    }
  };

  const restartApp = async () => {
    try {
      await RESTManagerInstance.restartApp();
      toast.success("App correctly restarted");
    } catch (e) {
      console.error(e);
      toast.error("Error while restarting app.");
    }
  };

  const closeDialogs = async () => {
    try {
      await RESTManagerInstance.closeDialogs();
      toast.success("Request issued correctly");
    } catch (e) {
      console.error(e);
      toast.error("Error while closing system dialogs.");
    }
  };

  const runBugreportz = async () => {
    try {
      await RESTManagerInstance.startBugreportz();
      toast.success("bugreportz correctly started");
    } catch (e) {
      console.error(e);
      toast.error("Error while starting bugreportz.");
    }
  };

  const downloadBugreport = async () => {
    try {
      const response = await RESTManagerInstance.downloadBugreport();

      // Create a URL for the blob
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", "bugreport.zip");
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (error) {
      toast.error("Failed to download bugreport.");
    }
  };

  const shutdown = async () => {
    try {
      await RESTManagerInstance.shutdown();
    } catch (e) {
      console.error(e);
      toast.error("Error while shutting down the device");
    }
  };

  const reboot = async () => {
    try {
      await RESTManagerInstance.reboot();
    } catch (e) {
      console.error(e);
      toast.error("Error while rebooting the device");
    }
  };

  // Cleanup forms when dialogs are closed:
  useEffect(() => {
    let timer: NodeJS.Timeout | null = null;
    if (featuresConfig.bugReportEnabled) {
      timer = setInterval(async function () {
        const res = await RESTManagerInstance.getBugreportzStatus();
        setBugreportStatus(res.data);
      }, 5000);
      getBugreportzStatus();
    }

    return () => {
      if (timer) {
        clearInterval(timer);
      }
    };
  }, []);

  return (
    <>
      {/*************
       *    Modals   *
       ***************/}

      {/* Start Activity Modal */}
      <StartActivityModal dialogRef={startActivityDialogRef} />

      {/* Start Broadcast Receiver Modal */}
      <StartBroadcastModal dialogRef={startBroadcastReceiverDialogRef} />

      {/* Start Service Modal */}
      <StartServiceModal dialogRef={startServiceDialogRef} />

      {/*************
       *   Content   *
       ***************/}
      <div className="w-full flex flex-col gap-2 select-none">
        <div className="flex gap-2 items-center mb-2">
          <MdSpaceDashboard size={32} />
          <h1 className="text-2xl font-semibold">Overview</h1>
        </div>

        {/* Device Info */}
        <div className="card bg-base-300 border border-base-300">
          <div className="card-body p-4">
            <div className="grid grid-cols-2 gap-6">
              <div>
                <div className="flex gap-2 items-center">
                  <IoInformationCircleOutline size={24} />
                  <p className="font-semibold text-base">Device</p>
                </div>
                <p className="text-base">{deviceInfo.model}</p>
              </div>

              <div>
                <div className="flex gap-2 items-center">
                  <IoLogoAndroid size={24} />
                  <p className="font-semibold text-base">Android Version</p>
                </div>
                <p className="text-base">{deviceInfo.version}</p>
              </div>

              <div>
                <div className="flex gap-2 items-center">
                  <TbVersions size={24} />
                  <p className="font-semibold text-base">Type</p>
                </div>
                <p className="text-base">{deviceInfo.deviceType}</p>
              </div>

              <div>
                <div className="flex gap-2 items-center">
                  <TbCpu size={24} />
                  <p className="font-semibold text-base">Processor</p>
                </div>
                <p className="text-base">{deviceInfo.architecture}</p>
              </div>
            </div>
          </div>
        </div>
        {/* Actions */}
        <div className="card bg-base-300 border border-base-300">
          <div className="card-body p-4">
            <div className="font-semibold text-lg peer-hover:bg-gray-600 peer-checked:mb-4">Actions</div>
            <div className="flex w-full justify-between items-center">
              <p>
                Restart <b>App</b>
              </p>
              <div className="join">
                <button className="btn btn-accent join-item rounded-r-md" onClick={restartApp}>
                  Restart
                </button>
              </div>
            </div>

            <div className="flex w-full justify-between items-center">
              <p>
                Close <b>System Dialogs</b>
              </p>
              <div className="join">
                <button className="btn btn-accent join-item rounded-r-md" onClick={closeDialogs}>
                  Close
                </button>
              </div>
            </div>

            {featuresConfig.startActivityEnabled && (
              <div className="flex w-full justify-between items-center">
                <p>
                  Start <b>Activity</b>
                </p>
                <div className="join">
                  <button
                    className="btn btn-info join-item rounded-r-md"
                    onClick={() => startActivityDialogRef.current?.showModal()}
                  >
                    Start
                  </button>
                </div>
              </div>
            )}

            {featuresConfig.startBroadcastReceiverEnabled && (
              <div className="flex w-full justify-between items-center">
                <p>
                  Send <b>Broadcast Intent</b>
                </p>
                <div className="join">
                  <button
                    className="btn btn-accent join-item rounded-r-md"
                    onClick={() => startBroadcastReceiverDialogRef.current?.showModal()}
                  >
                    Send
                  </button>
                </div>
              </div>
            )}

            {featuresConfig.startServiceEnabled && (
              <div className="flex w-full justify-between items-center">
                <p>
                  Start <b>Service</b>
                </p>
                <div className="join">
                  <button
                    className="btn btn-info join-item rounded-r-md"
                    onClick={() => startServiceDialogRef.current?.showModal()}
                  >
                    Start
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
        {/* Power Menu */}
        {isPowerMenuEnabled && (
          <div className="collapse collapse-arrow bg-base-300 border border-base-300">
            <input type="checkbox" name="power-accordion" className="peer" />
            <div className="collapse-title text-lg font-semibold peer-hover:bg-gray-600 peer-checked:mb-4">
              Power Menu
            </div>
            <div className="collapse-content text-sm flex items-center justify-between">
              <p>Power options let you shutdown or reboot the device.</p>
              <div className="flex gap-2">
                {featuresConfig.shutdownEnabled && (
                  <button className="btn btn-error" onClick={shutdown}>
                    Shutdown
                  </button>
                )}
                {featuresConfig.rebootEnabled && (
                  <button className="btn btn-info" onClick={reboot}>
                    Reboot
                  </button>
                )}
              </div>
            </div>
          </div>
        )}
        {/* Bug Report */}
        {featuresConfig.bugReportEnabled && (
          <div className="collapse collapse-arrow bg-base-300 border border-base-300">
            <input type="checkbox" name="bug-report-accordion" className="peer" />
            <div className="collapse-title text-lg font-semibold peer-hover:bg-gray-600 peer-checked:mb-4">
              Bug Report
            </div>
            <div className="collapse-content text-sm flex items-center justify-between">
              <span>
                Run the <pre className="inline">bugreportz</pre> tool and get the output file
              </span>
              <div className="flex items-center justify-center gap-2">
                <button className="btn btn-info" onClick={runBugreportz} disabled={bugreportStatus.isRunning}>
                  Run <pre>bugreportz</pre>
                </button>
                <button
                  className="btn btn-accent"
                  onClick={downloadBugreport}
                  disabled={!bugreportStatus.isBugreportAvailable}
                >
                  Download Bugreport
                </button>
              </div>
            </div>
          </div>
        )}
        {/* README */}
        <div className="collapse collapse-arrow bg-base-300 border border-base-300">
          <input type="checkbox" name="readme-accordion" className="peer" />
          <div className="collapse-title text-lg font-semibold peer-hover:bg-gray-600 peer-checked:mb-4">README</div>
          <div className="collapse-content text-sm leading-normal">
            <h3 className="text-base font-semibold my-2">What is DroidGround?</h3>
            <p>
              In traditional Capture the Flag (CTF) challenges, it's common to hide flags in files on a system,
              requiring attackers to exploit vulnerabilities to retrieve them. However, in the Android world, this
              approach doesn't work well. APK files are easily downloadable and reversible, so placing a flag on the
              device usually makes it trivial to extract using static analysis or emulator tricks. This severely limits
              the ability to create realistic, runtime-focused challenges.
            </p>
            <p>DroidGround is designed to solve this problem.</p>
            <p>
              It is a custom-built platform for hosting Android mobile hacking challenges in a controlled and realistic
              environment, where attackers are constrained just enough to require solving challenges in the intended
              way.
            </p>
            <p>
              Importantly, participants are jailed inside the app environment. The modularity of the tool allows to set
              if the user can or cannot spawn a shell, read arbitrary files, or sideload tools. Everything can be setup
              so that the only way to retrieve the flag is through understanding and exploiting the app itself, just
              like on a real, non-rooted device.
            </p>

            <h3 className="text-base font-semibold my-2">Why DroidGround?</h3>
            <ul className="list-disc list-inside">
              <li>
                <b>No shortcutting:</b> Flags cannot be extracted by reverse engineering the APK or scanning the
                filesystem
              </li>
              <li>
                <b>Realistic attack model:</b> Simulates real-world constraints where attackers do not have root or full
                device control
              </li>
              <li>
                <b>Interactive learning:</b> Encourages the use of dynamic tools like Frida under controlled conditions
              </li>
              <li>
                <b>Flexible challenge design:</b> Supports advanced CTF scenarios including memory inspection, insecure
                storage, IPC abuse, obfuscation, and more
              </li>
            </ul>

            <p>
              Whether you're an educator, a CTF organizer, or a security enthusiast, DroidGround provides a powerful way
              to explore and teach mobile application security in a realistic and engaging environment.
            </p>
          </div>
        </div>
      </div>
    </>
  );
};
