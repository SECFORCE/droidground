import { RESTManagerInstance } from "@client/api/rest";
import { useEffect, useState } from "react";
import { GiFiles } from "react-icons/gi";
import { FaFile, FaFolder, FaLink } from "react-icons/fa";
import { sleep } from "@shared/helpers";

type FileItemType = {
  name: string;
  path: string;
  type: "file" | "folder" | "link";
};

interface BreadcrumbsProps {
  path: string;
  onNavigate: (path: string) => void;
}

interface FileItemProps {
  item: FileItemType;
  onOpen: (item: FileItemType) => void;
}

const Breadcrumbs: React.FC<BreadcrumbsProps> = ({ path, onNavigate }) => {
  const segments = path.split("/").filter(Boolean);

  const buildPath = (index: number) => "/" + segments.slice(0, index + 1).join("/");

  return (
    <div className="text-sm breadcrumbs mb-2">
      <ul>
        <li>
          <button onClick={() => onNavigate("/")}>Root</button>
        </li>
        {segments.map((seg, idx) => (
          <li key={idx}>
            <button onClick={() => onNavigate(buildPath(idx))}>{seg}</button>
          </li>
        ))}
      </ul>
    </div>
  );
};

const typeToIconMapping = {
  file: <FaFile className="w-5 h-5" />,
  folder: <FaFolder className="w-5 h-5" />,
  link: <FaLink className="w-5 h-5" />,
};

const FileItem: React.FC<FileItemProps> = ({ item, onOpen }) => {
  return (
    <div
      className="flex items-center gap-3 p-3 rounded hover:bg-base-200 cursor-pointer transition"
      onClick={() => onOpen(item)}
    >
      {typeToIconMapping[item.type]}
      <span>{item.name}</span>
    </div>
  );
};

export const FileBrowser = () => {
  const [path, setPath] = useState("/");
  const [items, setItems] = useState<FileItemType[]>([]);
  const [loading, setLoading] = useState(false);

  const loadFolder = async (newPath: string) => {
    setLoading(true);
    try {
      const result = await RESTManagerInstance.getFiles({ path: newPath });
      setItems(
        result.data.result
          .filter(e => e.name !== "." && e.name !== ".." && !e.isCorrupted)
          .map(entry => {
            const fallbackPath = entry.linkTarget ?? `${newPath}/${entry.name}`;
            const permissionType = entry.permissions.startsWith("d") ? "folder" : "file";
            return {
              name: entry.name,
              path: entry.isSymlink ? fallbackPath : `${newPath}/${entry.name}`,
              type: entry.isSymlink ? "link" : permissionType,
            };
          }),
      );
      setPath(newPath);
    } catch (err) {
      console.error(err);
    } finally {
      await sleep(250);
      setLoading(false);
    }
  };

  useEffect(() => {
    loadFolder("/");
  }, []);

  const handleOpen = (item: FileItemType) => {
    if (item.type === "folder") {
      loadFolder(item.path);
    }
  };

  return (
    <div className="w-full flex flex-col gap-2">
      <div className="flex gap-2 items-center mb-2">
        <GiFiles size={32} />
        <h1 className="text-2xl font-semibold">File Browser</h1>
      </div>
      <div className="card bg-base-300 border border-base-300">
        <div className="card-body p-4">
          <div className="p-4 space-y-4">
            <Breadcrumbs path={path} onNavigate={loadFolder} />
            {loading ? (
              <span className="loading loading-spinner text-primary" />
            ) : items.length === 0 ? (
              <div className="text-center text-gray-500">
                This folder is empty (or you don't have the permissions to read it).
              </div>
            ) : (
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                {items.map(item => (
                  <FileItem key={item.path} item={item} onOpen={handleOpen} />
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
