import { http } from "@client/api/axios";
import {
  BugreportzStatusResponse,
  CompanionPackageInfos,
  DeviceInfoResponse,
  DroidGroundFeaturesResponse,
  FridaLibraryResponse,
  GetFilesRequest,
  GetFilesResponse,
  IGenericResultRes,
  StartActivityRequest,
  StartBroadcastRequest,
  StartServiceRequest,
} from "@shared/api";
import { REST_API_ENDPOINTS as E } from "@shared/endpoints";
import { AxiosResponse } from "axios";

// This functions are just used to wrap specific REST API calls
// Not using try/catch statement here so every specific component
// can handle the error in his own way
class RESTManager {
  async getFeatures(): Promise<AxiosResponse<DroidGroundFeaturesResponse>> {
    const res = await http.get<DroidGroundFeaturesResponse>(E.FEATURES);
    return res;
  }

  async getInfo(): Promise<AxiosResponse<DeviceInfoResponse>> {
    const res = await http.get<DeviceInfoResponse>(E.INFO);
    return res;
  }

  async startActivity(data: StartActivityRequest): Promise<AxiosResponse<IGenericResultRes>> {
    const res = await http.post<IGenericResultRes>(E.ACTIVITY, data);
    return res;
  }

  async startBroadcast(data: StartBroadcastRequest): Promise<AxiosResponse<IGenericResultRes>> {
    const res = await http.post<IGenericResultRes>(E.BROADCAST, data);
    return res;
  }

  async startService(data: StartServiceRequest): Promise<AxiosResponse<IGenericResultRes>> {
    const res = await http.post<IGenericResultRes>(E.SERVICE, data);
    return res;
  }

  async dumpLogcat(): Promise<AxiosResponse<IGenericResultRes>> {
    const res = await http.post<IGenericResultRes>(E.LOGCAT);
    return res;
  }

  async clearLogcat(): Promise<AxiosResponse<IGenericResultRes>> {
    const res = await http.delete<IGenericResultRes>(E.LOGCAT);
    return res;
  }

  async getFiles(data: GetFilesRequest): Promise<AxiosResponse<GetFilesResponse>> {
    const res = await http.post<GetFilesResponse>(E.FILES, data);
    return res;
  }

  async shutdown(): Promise<AxiosResponse<IGenericResultRes>> {
    const res = await http.post<IGenericResultRes>(E.SHUTDOWN);
    return res;
  }

  async reboot(): Promise<AxiosResponse<IGenericResultRes>> {
    const res = await http.post<IGenericResultRes>(E.REBOOT);
    return res;
  }

  async getBugreportzStatus(): Promise<AxiosResponse<BugreportzStatusResponse>> {
    const res = await http.get<BugreportzStatusResponse>(E.BUGREPORT_STATUS);
    return res;
  }

  async startBugreportz(): Promise<AxiosResponse<IGenericResultRes>> {
    const res = await http.post<IGenericResultRes>(E.BUGREPORT);
    return res;
  }

  async downloadBugreport(): Promise<AxiosResponse<any>> {
    const res = await http.get<any>(E.BUGREPORT, { responseType: "blob" });
    return res;
  }

  async getPackageInfos(): Promise<AxiosResponse<CompanionPackageInfos[]>> {
    const res = await http.get<CompanionPackageInfos[]>(E.PACKAGES);
    return res;
  }

  async installApk(formData: FormData): Promise<AxiosResponse<IGenericResultRes>> {
    const res = await http.post<IGenericResultRes>(E.APK, formData);
    return res;
  }

  async getFridaLibrary(): Promise<AxiosResponse<FridaLibraryResponse>> {
    const res = await http.get<FridaLibraryResponse>(E.LIBRARY);
    return res;
  }
}
export const RESTManagerInstance = new RESTManager();
