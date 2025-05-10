import { GiFiles } from "react-icons/gi";

export const FileBrowser: React.FC = () => {
    return (
        <div className="w-full flex flex-col gap-2">
            <div className="flex gap-2 items-center mb-2">
                <GiFiles size={32}/>
                <h1 className="text-2xl font-semibold">File Browser</h1>
            </div>
            <div className="card bg-base-300 border border-base-300">
                <div className="card-body p-4">
                    <h2 className="card-title">File Browser</h2>
                </div>
            </div>
        </div>
    )
}