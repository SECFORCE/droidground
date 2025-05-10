import { IoTerminalSharp } from "react-icons/io5";

export const Terminal: React.FC = () => {
    return (
        <div className="w-full flex flex-col gap-2">
            <div className="flex gap-2 items-center mb-2">
                <IoTerminalSharp size={32}/>
                <h1 className="text-2xl font-semibold">Terminal</h1>
            </div>
            <div className="card bg-base-300 border border-base-300">
                <div className="card-body p-4">
                    <h2 className="card-title">Terminal</h2>
                </div>
            </div>
        </div>
    )
}