import { RESTManagerInstance } from "@client/api/rest";
import { CompanionPackageInfos } from "@shared/api";
import { sleep } from "@shared/helpers";
import { useEffect, useRef, useState } from "react";
import toast from "react-hot-toast";
import { IoApps } from "react-icons/io5";
import { FiRefreshCcw } from "react-icons/fi";
import { InstallExploitAppModal, StartExploitAppModal } from "@client/components";

const toDatestring = (ts: number) => {
  return new Date(ts).toLocaleDateString("en-US", {
    year: "numeric",
    month: "long",
    day: "numeric",
  });
};

const toHumanReadableSize = (bytes: number, decimals = 2) => {
  if (bytes === 0) return "0 Bytes";

  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;

  const sizes = ["Bytes", "KB", "MB", "GB", "TB", "PB", "EB"];

  const i = Math.floor(Math.log(bytes) / Math.log(k));
  const size = parseFloat((bytes / Math.pow(k, i)).toFixed(dm));

  return `${size} ${sizes[i]}`;
};

export const AppManager: React.FC = () => {
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [packages, setPackages] = useState<CompanionPackageInfos[]>([]);
  const installExploitAppDialogRef = useRef<HTMLDialogElement | null>(null);
  const startExploitAppDialogRef = useRef<HTMLDialogElement | null>(null);

  const getPackageInfos = async () => {
    setIsLoading(true);
    try {
      const result = await RESTManagerInstance.getPackageInfos();
      setPackages(result.data);
      await sleep(500);
      toast.success("Packages info correctly retrieved.");
    } catch (e) {
      console.error(e);
      toast.error("Error while loading package info");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    getPackageInfos();
  }, []);

  const handleOnInstall = async () => {
    try {
      setIsLoading(true);
      const result = await RESTManagerInstance.getPackageInfos();
      setPackages(result.data);
    } catch (error) {
      console.error(error);
    } finally {
      setIsLoading(false);
    }
  };

  if (isLoading) {
    return (
      <div className="w-full flex flex-col gap-2">
        <div className="flex gap-2 items-center mb-2">
          <IoApps size={32} />
          <h1 className="text-2xl font-semibold">App Manager</h1>
        </div>
        <div className="card bg-base-300 border border-base-300">
          <div className="card-body p-4 max-h-screen">
            <span className="loading loading-spinner text-primary" />
          </div>
        </div>
      </div>
    );
  }

  return (
    <>
      {/*************
       *    Modals   *
       ***************/}

      {/* Install Exploit App Modal */}
      <InstallExploitAppModal dialogRef={installExploitAppDialogRef} onInstall={handleOnInstall} />

      {/* Start Exploit App Modal */}
      <StartExploitAppModal dialogRef={startExploitAppDialogRef} />

      {/*************
       *   Content   *
       ***************/}
      <div className="w-full flex flex-col gap-2">
        <div className="flex gap-2 items-center mb-2">
          <IoApps size={32} />
          <h1 className="text-2xl font-semibold select-none">App Manager</h1>
        </div>
        <div className="card bg-base-300 border border-base-300">
          <div className="card-body p-4 max-h-screen">
            <div className="card-title items-start justify-between mb-2 select-none flex flex-col lg:flex-row">
              <h2>Third-party Apps</h2>
              <div className="flex gap-2">
                <button className="btn btn-info" onClick={getPackageInfos}>
                  <FiRefreshCcw />
                </button>
                <button
                  className="btn btn-accent cursor-pointer whitespace-nowrap"
                  onClick={() => installExploitAppDialogRef.current?.showModal()}
                >
                  Install APK
                </button>
                <button
                  className="btn btn-error join-item rounded-r-md"
                  onClick={() => startExploitAppDialogRef.current?.showModal()}
                >
                  Start Exploit App
                </button>
              </div>
            </div>
            <p className="mb-2">
              If you are worried that other teams may start your exploit app (via another app through an explicit
              intent) you may add the <code className="inline">android.permission.DUMP</code> permission to the launcher
              activity so that other apps won't be able to start it.
            </p>
            <div className="overflow-x-auto">
              <table className="table table-pin-rows">
                {/* head */}
                <thead>
                  <tr>
                    <th></th>
                    <th>Name</th>
                    <th>Package Info</th>
                    <th>Size</th>
                    <th>Date Installed</th>
                    <th>Date Updated</th>
                  </tr>
                </thead>
                <tbody>
                  {packages.map((p, key) => {
                    return (
                      <tr className="hover:bg-base-200" key={key}>
                        <th>
                          <img src={p.icon} className="w-12 h-12" />
                        </th>
                        <td>{p.label}</td>
                        <td className="flex flex-col">
                          <span className="font-semibold">{p.packageName}</span>
                          <span className="text-xs">{p.versionName}</span>
                        </td>
                        <td>{toHumanReadableSize(p.apkSize)}</td>
                        <td>{toDatestring(p.firstInstallTime)}</td>
                        <td>{toDatestring(p.lastUpdateTime)}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </>
  );
};
