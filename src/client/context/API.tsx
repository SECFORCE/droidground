import { createContext, useEffect, useContext, ReactNode, useState } from "react";
import { DroidGroundFeatures } from "@shared/types";
import { DeviceInfoResponse } from "@shared/api";
import { RESTManagerInstance } from "@client/api/rest";

type APIContextType = {
  featuresConfig: DroidGroundFeatures;
  deviceInfo: DeviceInfoResponse;
};

const APIContext = createContext<APIContextType | undefined>(undefined);

export const APIProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [featuresConfig, setFeaturesConfig] = useState<DroidGroundFeatures>();
  const [deviceInfo, setDeviceInfo] = useState<DeviceInfoResponse>();
  const [error, setError] = useState<Error | null>(null);

  const getFeaturesConfig = async () => {
    try {
      const res = await RESTManagerInstance.getFeatures();
      setFeaturesConfig(res.data);
    } catch (e) {
      setError(e instanceof Error ? e : new Error("Unknown error"));
    }
  };

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
    getFeaturesConfig();
  }, []);

  // Throwing during render if an error occurred
  if (error) throw error;

  return (
    <APIContext.Provider
      value={{
        featuresConfig: featuresConfig as DroidGroundFeatures,
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
