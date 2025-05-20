import { RESTManagerInstance } from "@client/api/rest";
import { useState } from "react";
import toast from "react-hot-toast";
import { VscOutput } from "react-icons/vsc";

export const Logs: React.FC = () => {
  const [currentLogs, setCurrentLogs] = useState<string[]>([]);

  const dump = async () => {
    try {
      const res = await RESTManagerInstance.dumpLogcat();
      setCurrentLogs(res.data.result.split("\n"));
    } catch (e) {
      console.error(e);
      toast.error("Error while dumping logcat");
    }
  };

  const clear = async () => {
    try {
      await RESTManagerInstance.clearLogcat();
      setCurrentLogs([]);
    } catch (e) {
      console.error(e);
      toast.error("Error while clearing logcat");
    }
  };

  return (
    <div className="w-full flex flex-col gap-2">
      <div className="flex gap-2 items-center mb-2">
        <VscOutput size={32} />
        <h1 className="text-2xl font-semibold select-none">Logs</h1>
      </div>
      <div className="card bg-base-300 border border-base-300">
        <div className="card-body p-4">
          <div className="card-title justify-between select-none">
            <h2>Output</h2>
            <div className="flex gap-2">
              <button className="btn btn-info" onClick={dump}>
                Dump
              </button>
              <button className="btn btn-error" onClick={clear}>
                Clear
              </button>
            </div>
          </div>
          {currentLogs.length > 0 ? (
            <div className="code-mockup hide-before">
              {currentLogs.map((l, key) => (
                <pre key={key} className="text-accent text-wrap wrap-break-word break-all">
                  <code>{l}</code>
                </pre>
              ))}
            </div>
          ) : (
            <p className="text-error">There are currently no logs (up to 500 lines will be shown).</p>
          )}
        </div>
      </div>
    </div>
  );
};
