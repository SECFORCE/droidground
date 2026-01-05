import { useEffect, useState } from "react";
import { SubmitHandler, useFieldArray, useForm } from "react-hook-form";
import toast from "react-hot-toast";
import { RESTManagerInstance } from "@client/api/rest";
import { StartBroadcastRequest } from "@shared/api";
import { IntentExtraType } from "@shared/types";

interface IModalProps {
  dialogRef: React.RefObject<HTMLDialogElement | null>;
}

export const StartBroadcastModal: React.FC<IModalProps> = ({ dialogRef }) => {
  const [actionResult, setActionResult] = useState<string[]>([]);
  const {
    register,
    handleSubmit,
    reset,
    watch,
    control,
    formState: { errors },
  } = useForm<StartBroadcastRequest>({
    defaultValues: {
      extras: [],
    },
  });

  const { fields, append, remove } = useFieldArray({
    control,
    name: "extras",
  });

  useEffect(() => {
    const handleClose = () => {
      setActionResult([]);
      reset();
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

  const startBroadcastReceiver: SubmitHandler<StartBroadcastRequest> = async data => {
    if (!data.receiver && !data.action) {
      return;
    }

    try {
      const res = await RESTManagerInstance.startBroadcast(data);
      const resultLines = res.data.result.split("\n");
      setActionResult([`Command executed: ${res.data.command}`, ...resultLines]);
    } catch (e) {
      console.error(e);
      toast.error("Failed to send broadcast intent.");
    }
  };

  const selectedExtras = watch("extras");

  return (
    <dialog ref={dialogRef} className="modal">
      <div className="modal-box max-w-3xl">
        <h3 className="font-bold text-lg mb-4">Send Broadcast Intent</h3>
        <p className="mb-4">
          This will allow you send a <i>Broadcast Intent</i> <b>belonging to the target app only</b>!
        </p>
        <form onSubmit={handleSubmit(startBroadcastReceiver)} className="space-y-4">
          <input
            type="text"
            placeholder="Receiver (Full name)"
            className="input input-bordered w-full"
            {...register("receiver", { required: true })}
          />
          {errors.receiver && <p className="text-error text-sm">Receiver is required.</p>}

          <input
            type="text"
            placeholder="Action (optional)"
            className="input input-bordered w-full"
            {...register("action")}
          />

          {/* Extras Section */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="font-semibold">Intent Extras</span>
              <button
                type="button"
                className="btn btn-sm btn-outline"
                onClick={() => append({ key: "", type: IntentExtraType.STRING, value: "" })}
              >
                + Add Extra
              </button>
            </div>
            <div className="space-y-4">
              {fields.map((field, index) => (
                <div key={field.id} className="border p-4 rounded space-y-2">
                  <div className="flex gap-2">
                    <input
                      type="text"
                      placeholder="Key"
                      className="input input-bordered w-full"
                      {...register(`extras.${index}.key`, { required: true })}
                    />
                    <select
                      className="select select-bordered"
                      {...register(`extras.${index}.type`, { required: true })}
                    >
                      {Object.values(IntentExtraType).map(type => (
                        <option key={type} value={type}>
                          {type}
                        </option>
                      ))}
                    </select>
                  </div>

                  <input
                    {...register(`extras.${index}.value`, { required: true })}
                    type="text"
                    placeholder="Value"
                    className="input input-bordered w-full"
                  />

                  {/*
                  {watch(`extras.${index}.type`) !== IntentExtraType.NULL && (
                    <Controller
                      name={`extras.${index}.value`}
                      control={control}
                      render={field => (
                        <input {...field} type="text" placeholder="Value" className="input input-bordered w-full" />
                      )}
                    />
                  )}
                  */}

                  <div className="text-right">
                    <button type="button" className="btn btn-sm btn-error" onClick={() => remove(index)}>
                      Remove
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Result */}
          {actionResult.length > 0 && (
            <div className="flex flex-col justify-between mb-4 gap-4">
              <span className="font-semibold">Output</span>
              <div className="mockup-code w-full hide-before max-h-96 overflow-y-auto p-4">
                {actionResult.map((l, key) => (
                  <pre key={key} className="text-accent text-wrap wrap-break-word break-all">
                    <code>{l}</code>
                  </pre>
                ))}
              </div>
            </div>
          )}

          {/* Submit */}
          <div className="flex justify-end">
            <input className="btn btn-primary" type="submit" value="Send Broadcast" />
          </div>
        </form>
      </div>
      <form method="dialog" className="modal-backdrop">
        <button>close</button>
      </form>
    </dialog>
  );
};
