import { useState } from "react";
import { IoInformationCircleOutline, IoLogoAndroid } from "react-icons/io5";
import { TbCpu, TbVersions } from "react-icons/tb";
import { MdSpaceDashboard } from "react-icons/md";

export const Overview: React.FC = () => {
  const [activity, setActivity] = useState<string>('');

  const startActivity = async () => {
    console.log(activity)
  }

  return (
    <div className="w-full flex flex-col gap-2">
        <div className="flex gap-2 items-center mb-2">
            <MdSpaceDashboard size={32}/>
            <h1 className="text-2xl font-semibold">Overview</h1>
        </div>
        <div className="card bg-base-300 border border-base-300">
            <div className="card-body p-4">
            <div className="grid grid-cols-2 gap-6">
                <div>
                <div className="flex gap-2 items-center">
                    <IoInformationCircleOutline size={24}/>
                    <p className="font-semibold text-base">Device</p>
                </div>
                <p className="text-base">Pixel 7</p>
                </div>

                <div>
                <div className="flex gap-2 items-center">
                    <IoLogoAndroid size={24}/>
                    <p className="font-semibold text-base">Android Version</p>
                </div>
                <p className="text-base">14 (Upside Down Cake)</p>
                </div>


                <div>
                <div className="flex gap-2 items-center">
                    <TbVersions size={24}/>
                    <p className="font-semibold text-base">Type</p>
                </div>
                <p className="text-base">Emulator</p>
                </div>

                <div>
                <div className="flex gap-2 items-center">
                    <TbCpu size={24}/>
                    <p className="font-semibold text-base">Processor</p>
                </div>
                <p className="text-base">x86</p>
                </div>

            </div>
            </div>
        </div>
        <div className="collapse collapse-arrow bg-base-300 border border-base-300">
            <input type="checkbox" name="actions-accordion" className="peer" />
            <div className="collapse-title font-semibold peer-hover:bg-gray-600 peer-checked:mb-4">Actions</div>
            <div className="collapse-content text-sm flex items-center justify-between">
            <p>Open Activity</p>
            <div className="join">
                <input type="text" className="input min-w-96 rounded-l-md focus:outline-0" placeholder="com.example.app/.MainActivity" required onChange={e => setActivity(e.target.value)} />
                <button className="btn btn-info join-item rounded-r-md" onClick={startActivity}>Start</button>
            </div>
            </div>
        </div>
        <div className="collapse collapse-arrow bg-base-300 border border-base-300">
            <input type="checkbox" name="power-accordion" className="peer" />
            <div className="collapse-title font-semibold peer-hover:bg-gray-600 peer-checked:mb-4">Power Menu</div>
            <div className="collapse-content text-sm flex items-center justify-between">
                <p>Power options let you shutdown or reboot the device.</p>
                <div className="flex gap-2">
                <button className="btn btn-error">Shutdown</button>
                <button className="btn btn-info">Reboot</button>
                </div>
            </div>
        </div>
        <div className="collapse collapse-arrow bg-base-300 border border-base-300">
            <input type="checkbox" name="bug-report-accordion" className="peer" />
            <div className="collapse-title font-semibold peer-hover:bg-gray-600 peer-checked:mb-4">Bug Report</div>
            <div className="collapse-content text-sm flex items-center justify-between">
            <p>Run the <pre className="inline">bugreportz</pre> tool and get the output file</p>
            <button className="btn btn-info">Run <pre>bugreportz</pre></button>
            </div>
        </div>
        <div className="collapse collapse-arrow bg-base-300 border border-base-300">
            <input type="checkbox" name="readme-accordion" className="peer" />
            <div className="collapse-title font-semibold peer-hover:bg-gray-600 peer-checked:mb-4">README</div>
            <div className="collapse-content text-sm leading-[1.5]">
            <h3 className="text-base font-semibold my-2">What is DroidGround?</h3>
            <p>
                In traditional Capture the Flag (CTF) challenges, it's common to hide flags in files on a system, requiring attackers to exploit vulnerabilities to retrieve them. However, in the Android world, this approach doesn't work well. APK files are easily downloadable and reversible, so placing a flag on the device usually makes it trivial to extract using static analysis or emulator tricks. This severely limits the ability to create realistic, runtime-focused challenges.
            </p>
            <p>
                DroidGround is designed to solve this problem.
            </p>
            <p>
                It is a custom-built platform for hosting Android mobile hacking challenges in a controlled and realistic environment, where attackers are constrained just enough to require solving challenges in the intended way.
            </p>
            <p>
                Importantly, participants are jailed inside the app environment. The modularity of the tool allows to set if the user can or cannot spawn a shell, read arbitrary files, or sideload tools. Everything can be setup so that the only way to retrieve the flag is through understanding and exploiting the app itself, just like on a real, non-rooted device.
            </p>

            <h3 className="text-base font-semibold my-2">Why DroidGround?</h3>
            <ul className="list-disc list-inside">
                <li><b>No shortcutting:</b> Flags cannot be extracted by reverse engineering the APK or scanning the filesystem</li>
                <li><b>Realistic attack model:</b> Simulates real-world constraints where attackers do not have root or full device control</li>
                <li><b>Interactive learning:</b> Encourages the use of dynamic tools like Frida under controlled conditions</li>
                <li><b>Flexible challenge design:</b> Supports advanced CTF scenarios including memory inspection, insecure storage, IPC abuse, obfuscation, and more</li>
            </ul>

            <p>
                Whether you're an educator, a CTF organizer, or a security enthusiast, DroidGround provides a powerful way to explore and teach mobile application security in a realistic and engaging environment.
            </p>
            </div>
        </div>
    </div>
  )
}