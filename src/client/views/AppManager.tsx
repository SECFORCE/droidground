import { RESTManagerInstance } from "@client/api/rest";
import { CompanionPackageInfos } from "@shared/api";
import { sleep } from "@shared/helpers";
import { useEffect, useState } from "react";
import toast from "react-hot-toast";
import { IoApps } from "react-icons/io5";
import { FiRefreshCcw } from "react-icons/fi";

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
  const [apkFile, setApkFile] = useState<File | null>(null);

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

  const handleInstall = async (e: React.ChangeEvent<HTMLInputElement>): Promise<void> => {
    e.preventDefault();

    const fileToUpload = e.target.files && e.target.files.length > 0 ? e.target.files[0] : null;
    if (!fileToUpload) {
      toast.error("Please select an APK file to upload.");
      return;
    }

    const formData = new FormData();
    formData.append("apkFile", fileToUpload);

    try {
      setIsLoading(true);
      await RESTManagerInstance.installApk(formData);
      const result = await RESTManagerInstance.getPackageInfos();
      setPackages(result.data);
      await sleep(500);
      // Display the upload summary
      toast.success("APK correctly installed");
    } catch (error) {
      console.error(error);
      toast.error("Failed to upload file.");
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
    <div className="w-full flex flex-col gap-2">
      <div className="flex gap-2 items-center mb-2">
        <IoApps size={32} />
        <h1 className="text-2xl font-semibold">App Manager</h1>
      </div>
      <div className="card bg-base-300 border border-base-300">
        <div className="card-body p-4 max-h-screen">
          <div className="card-title justify-between mb-2">
            <h2>Third-party Apps</h2>
            <div className="flex gap-2">
              <button className="btn btn-info" onClick={getPackageInfos}>
                <FiRefreshCcw />
              </button>
              <div>
                <input type="file" accept=".apk" id="apk-upload" className="hidden" onChange={handleInstall} />
                <label htmlFor="apk-upload" className="btn btn-accent cursor-pointer whitespace-nowrap">
                  Install APK
                </label>
              </div>
            </div>
          </div>
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
                        <img src={p.icon} className="w-[3rem] h-[3rem]" />
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
  );
};
