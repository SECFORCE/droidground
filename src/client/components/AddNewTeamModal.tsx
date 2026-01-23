import { useEffect, useState } from "react";
import toast from "react-hot-toast";
import { RESTManagerInstance } from "@client/api/rest";

interface IModalProps {
  dialogRef: React.RefObject<HTMLDialogElement | null>;
}

export const AddNewTeamModal: React.FC<IModalProps> = ({ dialogRef }) => {
  const [requestResult, setRequestResult] = useState<string>("");

  useEffect(() => {
    const handleClose = () => {
      setRequestResult("");
    };

    const dialog = dialogRef.current;
    if (dialog) {
      dialog.addEventListener("close", handleClose);
    }

    return () => {
      if (dialog) {
        dialog.removeEventListener("close", handleClose);
      }
    };
  }, []);

  const getTeamToken = async () => {
    try {
      const res = await RESTManagerInstance.addNewTeam();
      setRequestResult(`New Team Token generated: ${res.data.teamToken}`);
    } catch (e) {
      console.error(e);
      toast.error("Error while generating new Team Token.");
    }
  };

  return (
    <dialog ref={dialogRef} className="modal">
      <div className="modal-box max-w-3xl">
        <h3 className="font-bold text-lg mb-4">Get Team Token</h3>
        <p className="mb-4">
          This will allow you to get a new Team Token which is <b>required</b> to install and run <i>exploit apps</i>{" "}
          and for the <i>Exploit Server</i> as well.
        </p>
        <div className="space-y-4">
          {/* Result */}
          {requestResult.length > 0 && (
            <div className="flex flex-col justify-between mb-4 gap-4">
              <span className="font-semibold">Output</span>
              <div className="mockup-code w-full hide-before max-h-96 overflow-y-auto p-4">
                <pre className="text-accent text-wrap wrap-break-word break-all">
                  <code>{requestResult}</code>
                </pre>
              </div>
            </div>
          )}

          {/* Submit */}
          <div className="flex justify-end">
            <input onClick={getTeamToken} className="btn btn-primary" value="Get Token" />
          </div>
        </div>
      </div>
      <form method="dialog" className="modal-backdrop">
        <button>close</button>
      </form>
    </dialog>
  );
};
