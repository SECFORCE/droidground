import { RESTManagerInstance } from "@client/api/rest";
import { useWebSocket } from "@client/context/WebSocket";
import { RunFridaScriptRequest } from "@shared/api";
import { WSCallback, WSMessageType } from "@shared/types";
import { useEffect, useState } from "react";
import { SubmitHandler, useForm } from "react-hook-form";
import toast from "react-hot-toast";
import { FaCode } from "react-icons/fa";
import { PiWarningBold } from "react-icons/pi";

const fridaScriptPlaceholder = `// Dummy Frida script
setImmediate(function() {
    send('Hello, world!');
});`

export const Frida: React.FC = () => {
    const { subscribe, unsubscribe } = useWebSocket();
    const runFridaScriptForm = useForm<RunFridaScriptRequest>();
    const code = runFridaScriptForm.watch('script');
    const lines = code ? code.split('\n') : [];
    const [fridaOutput, setFridaOutput] = useState<string>("");

    const runFridaScript: SubmitHandler<RunFridaScriptRequest> = async (data) => {
        try {
            await RESTManagerInstance.runFridaScript(data);
        } catch (e) {
            console.error(e);
            toast.error("Error while running Frida script.")
        }
    }

    const getFridaOutput = async () => {
        try {
            const res = await RESTManagerInstance.getFridaOutput();
            setFridaOutput(res.data.output);
        } catch (e) {
            console.error(e);
            toast.error("Error while getting Frida output.")
        }
    }

    useEffect(() => {
        const outputListener: WSCallback = (_metadata, _binaryData) => getFridaOutput()
        subscribe(WSMessageType.FRIDA_OUTPUT, outputListener)

        return () => {
            unsubscribe(WSMessageType.FRIDA_OUTPUT, outputListener)
          }

    }, [])

    return (
        <div className="w-full flex flex-col gap-2">
            <div className="flex gap-2 items-center mb-2">
                <FaCode size={32}/>
                <h1 className="text-2xl font-semibold">Frida</h1>
            </div>
            <div className="card bg-base-300 border border-base-300">
                <div className="card-body p-4">
                    <div role="alert" className="alert alert-warning">
                        <PiWarningBold size={20} />
                        <span>To get the output you <b>have to use</b> the <pre className="inline">send</pre> function in your <i>Frida</i> script.</span>
                    </div>
                    <p>Write your script in the editor below and run it!</p>
                    <div className="bg-neutral relative p-0 overflow-hidden">
                        {/* Line Numbers */}
                        <div className="absolute top-0 left-0 h-full w-10 bg-base-200 text-base-content opacity-50 text-right pr-2 pt-4 text-xs select-none leading-[1.25rem]">
                        {lines.map((_, idx) => (
                            <div key={idx}>{idx + 1}</div>
                        ))}
                        </div>
                        <form onSubmit={runFridaScriptForm.handleSubmit(runFridaScript)}>
                            {/* Textarea over code lines */}
                            <textarea
                            className="pl-12 pr-4 pt-4 pb-4 w-full h-full resize-none font-mono text-sm bg-transparent text-base-content focus:outline-none"
                            defaultValue={fridaScriptPlaceholder}
                            rows={lines.length}
                            spellCheck={false}
                            {...runFridaScriptForm.register('script', {required: true, minLength: 20})}
                            />

                            <input className="absolute btn btn-info z-20 top-2 right-2" type="submit" value="Run" />
                        </form>
                    </div>

                    <p className="text-base mt-2 font-semibold">Output</p>
                    <div className="mockup-code w-full hide-before">
                        {fridaOutput.length > 0 ? (
                            <>
                            {fridaOutput.split('\n').map((l, key) => (
                                <pre key={key} className="text-accent">
                                    <code>{l}</code>
                                </pre>
                            ))}
                            </>
                        ): (
                            <pre className="text-error"><code>No output</code></pre>
                        )}
                    </div>
                </div>
            </div>
        </div>
    )
}