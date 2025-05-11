import { BsAndroid2 } from "react-icons/bs";

export const Error: React.FC = () => {
    return (
      <div className="hero">
        <div className="hero-content text-center">
          <div className="max-w-md">
            <div className="flex items-center text-emerald-600">
                <h1 className="text-[12rem] leading-none select-none mr-[-2rem] tstroke">Err</h1>
                <BsAndroid2 size={140} className="text-shadow-black text-shadow-lg z-20 stroke-black stroke-[0.5]" stroke="#000"/>
                <h1 className="text-[12rem] leading-none select-none ml-[-2rem] tstroke">r</h1>
            </div>
            <h1 className="mb-5 font-bold opacity-20 text-2xl">A fatal exception has occurred in the main thread. Try to reboot the device</h1>
            <a className="btn btn-info " href="/">Reload</a>
          </div>
        </div>
      </div>
    )
  }