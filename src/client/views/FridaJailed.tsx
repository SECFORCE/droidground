import { useEffect, useRef, useState } from "react";
import { FormProvider, SubmitHandler, useFieldArray, useForm, useFormContext, useWatch } from "react-hook-form";
import toast from "react-hot-toast";
import { FaCode } from "react-icons/fa";
import { RESTManagerInstance } from "@client/api/rest";
import { sleep } from "@shared/helpers";
import { FridaLibrary } from "@shared/types";
import { StartFridaLibraryScriptRequest } from "@shared/api";
import { WEBSOCKET_ENDPOINTS } from "@shared/endpoints";
import { PiWarningBold } from "react-icons/pi";

type PrimitiveType = "string" | "number" | "boolean";
type FieldType = PrimitiveType | "array";

interface KeyValue {
  key: string;
  type: FieldType;
  value?: string;
  arrayValues?: { type: PrimitiveType; value: string }[];
}

interface FormValues {
  scriptName: string;
  entries: KeyValue[];
}

interface ArrayFieldEditorProps {
  entryIndex: number;
}

const parsePrimitive = (type: PrimitiveType, raw: any): string | number | boolean => {
  if (type === "number") return Number(raw);
  if (type === "boolean") return raw === "true" || raw === true;
  return raw;
};

const parseValue = (entry: KeyValue): any => {
  if (entry.type === "array") {
    return entry.arrayValues?.map(el => parsePrimitive(el.type, el.value)) ?? [];
  }
  return parsePrimitive(entry.type as PrimitiveType, entry.value || "");
};

const ArrayFieldEditor: React.FC<ArrayFieldEditorProps> = ({ entryIndex }) => {
  const { control, register } = useFormContext();

  const { fields, append, remove } = useFieldArray({
    control,
    name: `entries.${entryIndex}.arrayValues`,
  });

  // ✅ Watch all array types for this entry
  const arrayValues = useWatch({
    control,
    name: `entries.${entryIndex}.arrayValues`,
  });

  return (
    <div className="space-y-2">
      <label className="label">
        <span className="label-text">Array Elements</span>
      </label>

      {fields.map((field, idx) => {
        const selectedType = arrayValues?.[idx]?.type;

        const typeFieldName = `entries.${entryIndex}.arrayValues.${idx}.type` as const;
        const valueFieldName = `entries.${entryIndex}.arrayValues.${idx}.value` as const;

        return (
          <div key={field.id} className="flex gap-2 items-center">
            {/* Type selector */}
            <select {...register(typeFieldName)} className="select w-1/4">
              <option value="string">String</option>
              <option value="number">Number</option>
              <option value="boolean">Boolean</option>
            </select>

            {/* Value input */}
            {selectedType === "boolean" ? (
              <input type="checkbox" {...register(valueFieldName, { required: false })} className="toggle" />
            ) : (
              <input
                type={selectedType === "number" ? "number" : "text"}
                {...register(valueFieldName, {
                  required: "Value required",
                })}
                className="input w-2/4"
                placeholder={selectedType === "number" ? "e.g. 123" : "e.g. hello"}
              />
            )}

            {/* Remove button */}
            <button type="button" onClick={() => remove(idx)} className="btn btn-sm btn-error">
              Remove
            </button>
          </div>
        );
      })}

      <button type="button" onClick={() => append({ type: "string", value: "" })} className="btn btn-sm btn-outline">
        Add Array Element
      </button>
    </div>
  );
};

const ObjectBuilder: React.FC = () => {
  const methods = useFormContext<FormValues>();

  const {
    control,
    register,
    formState: { errors },
    watch,
  } = methods;

  const { fields, append, remove } = useFieldArray({
    control,
    name: "entries",
  });

  const watchedTypes = useWatch({ control, name: "entries" })?.map(entry => entry?.type);
  const allWatchedFormValues = watch();

  const getPreview = (values: FormValues): string[] => {
    const result: Record<string, any> = {};
    values.entries.forEach(entry => {
      if (entry.key) {
        result[entry.key] = parseValue(entry);
      }
    });
    return JSON.stringify(result, null, 2).split("\n");
  };

  return (
    <div className="space-y-6">
      <div className="space-y-6">
        {fields.map((field, index) => {
          const entryType = watchedTypes?.[index];

          return (
            <div key={field.id} className="shadow-md rounded-xl p-4 space-y-4 bg-base-200">
              <div className="flex gap-4 items-start flex-wrap">
                <div className="form-control w-full md:w-1/4">
                  <label className="label">
                    <span className="label-text">Key</span>
                  </label>
                  <input
                    {...register(`entries.${index}.key`, { required: "Key is required" })}
                    className="input w-full"
                    placeholder="e.g. age"
                  />
                  {errors.entries?.[index]?.key && (
                    <span className="text-error text-sm">{errors.entries[index]?.key?.message}</span>
                  )}
                </div>

                <div className="form-control w-full md:w-1/4">
                  <label className="label">
                    <span className="label-text">Type</span>
                  </label>
                  <select {...register(`entries.${index}.type`)} className="select w-full">
                    <option value="string">String</option>
                    <option value="number">Number</option>
                    <option value="boolean">Boolean</option>
                    <option value="array">Array</option>
                  </select>
                </div>

                {entryType !== "array" && (
                  <div className="form-control w-full md:w-1/3">
                    <label className="label">
                      <span className="label-text">Value</span>
                    </label>

                    {entryType === "boolean" ? (
                      <input
                        type="checkbox"
                        {...register(`entries.${index}.value`, { required: false })}
                        className="toggle"
                      />
                    ) : (
                      <input
                        type={entryType === "number" ? "number" : "text"}
                        {...register(`entries.${index}.value`, {
                          required: "Value is required",
                        })}
                        className="input w-full"
                        placeholder={entryType === "number" ? "e.g. 42" : "e.g. hello"}
                      />
                    )}

                    {errors.entries?.[index]?.value && (
                      <span className="text-error text-sm">{errors.entries[index]?.value?.message}</span>
                    )}
                  </div>
                )}
              </div>

              {entryType === "array" && <ArrayFieldEditor entryIndex={index} />}

              <div className="text-right">
                <button type="button" onClick={() => remove(index)} className="btn btn-sm btn-error">
                  Remove Entry
                </button>
              </div>
            </div>
          );
        })}

        <div className="w-full">
          <button
            type="button"
            className="btn btn-info w-full"
            onClick={() => append({ key: "", type: "string", value: "", arrayValues: [] })}
          >
            Add Entry
          </button>
        </div>

        <div>
          <h2 className="text-xl font-semibold">Current Object</h2>
          <div className="mockup-code w-full hide-before max-h-96 overflow-y-auto mt-4">
            {getPreview(allWatchedFormValues).map((l, key) => (
              <pre key={key} className="text-accent">
                <code>{l}</code>
              </pre>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export const FridaJailed: React.FC = () => {
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isObjectBuilderVisible, setIsObjectBuilderVisible] = useState<boolean>(false);
  const [fridaLibrary, setFridaLibrary] = useState<FridaLibrary>([]);
  const startFridaScriptForm = useForm<FormValues>({
    defaultValues: { entries: [] },
  });
  const [fridaOutput, setFridaOutput] = useState<string[]>([]);
  const socketRef = useRef<WebSocket | null>(null);
  const [isRunDisabled, setIsRunDisabled] = useState<boolean>(false);
  const [isStopDisabled, setIsStopDisabled] = useState<boolean>(true);
  const scriptName = startFridaScriptForm.watch("scriptName");

  const socketSetup = (data: StartFridaLibraryScriptRequest) => {
    const wsBaseUrl = `ws://${window.location.host}`; //TODO: Move to wss at some point
    const socket = new WebSocket(`${wsBaseUrl}${WEBSOCKET_ENDPOINTS.FRIDA}`);
    socketRef.current = socket;

    // When data comes from backend, write to terminal
    socket.addEventListener("message", event => {
      setFridaOutput(old => [...old, event.data]);
    });

    socket.addEventListener("open", async () => {
      setIsRunDisabled(true);
      socket.send(JSON.stringify(data));
      await sleep(1000);
      setIsRunDisabled(false);
      setIsStopDisabled(false);
    });

    socket.addEventListener("close", () => {
      setIsStopDisabled(true);
    });

    return () => {
      socket.close();
    };
  };

  const stopScript = () => {
    if (socketRef.current?.OPEN) {
      socketRef.current.close();
      setFridaOutput(old => [...old, "[Frida script exited]"]);
    }
  };

  const loadLibrary = async () => {
    setIsLoading(true);
    try {
      const result = await RESTManagerInstance.getFridaLibrary();
      setFridaLibrary(result.data.library);
      await sleep(500);
    } catch (e) {
      console.error(e);
      toast.error("Error while loading Frida library");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadLibrary();
  }, []);

  const toggleObjectBuilder = () => {
    if (isObjectBuilderVisible) {
      startFridaScriptForm.resetField("entries");
    }
    setIsObjectBuilderVisible(old => !old);
  };

  const runScript: SubmitHandler<FormValues> = async data => {
    const result: Record<string, any> = {};
    data.entries.forEach(entry => {
      if (entry.key) {
        result[entry.key] = parseValue(entry);
      }
    });
    const socketData: StartFridaLibraryScriptRequest = { scriptName: data.scriptName, args: result };
    stopScript();
    setFridaOutput([]);
    return socketSetup(socketData);
  };

  const renderScriptContent = (scriptName: string) => {
    const fridaEl = fridaLibrary.find(el => el.filename === scriptName);
    if (!fridaEl) {
      return;
    }

    return (
      <div>
        <h2 className="text-xl font-semibold my-2">Script Content</h2>
        <div className="mockup-code w-full hide-before max-h-96 overflow-y-auto">
          {fridaEl.content.split("\n").map((l, key) => (
            <pre key={key} className="text-accent">
              <code>{l}</code>
            </pre>
          ))}
        </div>
      </div>
    );
  };

  if (isLoading) {
    return (
      <div className="w-full flex flex-col gap-2">
        <div className="flex gap-2 items-center mb-2">
          <FaCode size={32} />
          <h1 className="text-2xl font-semibold select-none">Frida</h1>
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
        <FaCode size={32} />
        <h1 className="text-2xl font-semibold select-none">Frida</h1>
      </div>
      <div className="card bg-base-300 border border-base-300">
        <div className="card-body p-4">
          <div role="alert" className="alert alert-warning select-none">
            <PiWarningBold size={20} />
            <span>
              In order to make this work you have to send a <b>correct</b> (or empty) <code>args</code> object which
              matches the script you've chosen.
            </span>
          </div>
          <FormProvider {...startFridaScriptForm}>
            <form onSubmit={startFridaScriptForm.handleSubmit(runScript)}>
              {/* Script Selection */}
              <div>
                <h2 className="text-xl font-semibold">Library Script</h2>
                <p className="my-2">Select the script you want to run.</p>
                <select
                  defaultValue=""
                  className="select w-full mb-2"
                  {...startFridaScriptForm.register("scriptName", { required: true })}
                >
                  <option value="" disabled={true}>
                    Pick a script
                  </option>
                  {fridaLibrary.map((el, key) => (
                    <option value={el.filename} key={key}>{`${el.filename} - ${el.description}`}</option>
                  ))}
                </select>
                {startFridaScriptForm.formState.errors.scriptName && (
                  <p className="text-error text-sm">Script name is required.</p>
                )}
              </div>

              {/* Script output */}
              {scriptName !== "" && renderScriptContent(scriptName)}

              {/* Args Object Creation */}
              <div className="mt-2">
                <div className="flex justify-between select-none">
                  <h2 className="text-xl font-semibold">Args Object</h2>
                  <button
                    type="button"
                    className={`btn ${isObjectBuilderVisible ? "btn-error" : "btn-info"}`}
                    onClick={toggleObjectBuilder}
                  >
                    {isObjectBuilderVisible ? "Remove args Object" : "Add args Object"}
                  </button>
                </div>
                <p className="my-2">
                  Create the <code className="inline">args</code> object which will be passed to the{" "}
                  <code className="inline">run</code> function upon execution.
                </p>

                {isObjectBuilderVisible && <ObjectBuilder />}
              </div>

              {/* Script output */}
              <div>
                <h2 className="text-xl font-semibold my-2">Script Output</h2>
                <div className="mockup-code w-full hide-before max-h-96 overflow-y-auto">
                  {socketRef.current ? (
                    <>
                      {fridaOutput.map((l, key) => (
                        <pre key={key} className="text-accent">
                          <code>{l}</code>
                        </pre>
                      ))}
                    </>
                  ) : (
                    <pre className="text-error">
                      <code>No output</code>
                    </pre>
                  )}
                </div>
              </div>

              <div className="flex gap-2 mt-2">
                <button
                  type="submit"
                  className="btn btn-success flex-1"
                  disabled={isRunDisabled || !startFridaScriptForm.formState.isValid}
                >
                  {isObjectBuilderVisible ? "Run with current object" : "Run without args"}
                </button>
                <button disabled={isStopDisabled} className="btn btn-error flex-1" onClick={stopScript}>
                  Stop
                </button>
              </div>
            </form>
          </FormProvider>
        </div>
      </div>
    </div>
  );
};
