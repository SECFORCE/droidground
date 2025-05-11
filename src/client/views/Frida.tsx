import { useState } from "react";
import { FaCode } from "react-icons/fa";
import { PiWarningBold } from "react-icons/pi";

const fridaScriptPlaceholder = `// Dummy Frida script
setImmediate(function() {
    send('Hello, world!');
});`

export const Frida: React.FC = () => {
    const [code, setCode] = useState<string>(fridaScriptPlaceholder);  
    const lines = code.split('\n');

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
                
                        {/* Textarea over code lines */}
                        <textarea
                        className="pl-12 pr-4 pt-4 pb-4 w-full h-full resize-none font-mono text-sm bg-transparent text-base-content focus:outline-none"
                        value={code}
                        onChange={(e) => setCode(e.target.value)}
                        rows={lines.length}
                        spellCheck={false}
                        />

                        <button className="absolute btn btn-info z-20 top-2 right-2">Run</button>
                    </div>

                    <p className="text-base mt-2 font-semibold">Output</p>
                    <div className="mockup-code w-full hide-before">
                        <pre className="text-accent"><code>Done!</code></pre>
                    </div>
                </div>
            </div>
        </div>
    )
}