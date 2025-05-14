import { createContext, useEffect, useContext, ReactNode, useState } from "react";
import { DroidGroundFeatures } from "@shared/types";
import { DeviceInfoResponse } from "@shared/api";
import { RESTManagerInstance } from "@client/api/rest";
import toast from "react-hot-toast";

type APIContextType = {
  featuresConfig: DroidGroundFeatures;
  deviceInfo: DeviceInfoResponse;
};

const APIContext = createContext<APIContextType | undefined>(undefined);

const featuresConfig: DroidGroundFeatures = {
  appManagerEnabled: !(import.meta.env.DROIDGROUND_APP_MANAGER_DISABLED === "true"),
  bugReportEnabled: !(import.meta.env.DROIDGROUND_BUG_REPORT_DISABLED === "true"),
  fileBrowserEnabled: !(import.meta.env.DROIDGROUND_FILE_BROWSER_DISABLED === "true"),
  fridaEnabled: !(import.meta.env.DROIDGROUND_FRIDA_DISABLED === "true"),
  logcatEnabled: !(import.meta.env.DROIDGROUND_LOGCAT_DISABLED === "true"),
  rebootEnabled: !(import.meta.env.DROIDGROUND_REBOOT_DISABLED === "true"),
  shutdownEnabled: !(import.meta.env.DROIDGROUND_SHUTDOWN_DISABLED === "true"),
  startActivityEnabled: !(import.meta.env.DROIDGROUND_START_ACTIVITY_DISABLED === "true"),
  startBroadcastReceiverEnabled: !(import.meta.env.DROIDGROUND_START_RECEIVER_DISABLED === "true"),
  startServiceEnabled: !(import.meta.env.DROIDGROUND_START_SERVICE_DISABLED === "true"),
  terminalEnabled: !(import.meta.env.DROIDGROUND_TERMINAL_DISABLED === "true"),
};

export const APIProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [deviceInfo, setDeviceInfo] = useState<DeviceInfoResponse>();
  const [error, setError] = useState<Error | null>(null);

  const getInfo = async () => {
    try {
      const res = await RESTManagerInstance.getInfo();
      setDeviceInfo(res.data);
    } catch (e) {
      setError(e instanceof Error ? e : new Error("Unknown error"));
    }
  };

  useEffect(() => {
    getInfo();
  }, []);

  // Throwing during render if an error occurred
  if (error) throw error;

  return (
    <APIContext.Provider
      value={{
        featuresConfig,
        deviceInfo: deviceInfo as DeviceInfoResponse,
      }}
    >
      {children}
    </APIContext.Provider>
  );
};

export const useAPI = () => {
  const context = useContext(APIContext);
  if (!context) {
    throw new Error("useAPI must be used within a APIProvider");
  }
  return context;
};
