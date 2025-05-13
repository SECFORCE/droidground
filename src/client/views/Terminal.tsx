import { useEffect, useRef, useState } from "react"
import { Terminal as XTerminal } from "@xterm/xterm"
import { FitAddon } from "@xterm/addon-fit"
import { SearchAddon } from "@xterm/addon-search"
import { IoTerminalSharp } from "react-icons/io5";
import "@xterm/xterm/css/xterm.css"

const fitAddon = new FitAddon()
const searchAddon = new SearchAddon()

interface ITerminalComponentProps {
  setReconnectButtonVisible: (isVisible: boolean) => void;
}

const TerminalComponent: React.FC<ITerminalComponentProps>  = ({ setReconnectButtonVisible }: ITerminalComponentProps) => {
    const terminalRef = useRef<HTMLDivElement>(null);
    const socketRef = useRef<WebSocket | null>(null);
    const termRef = useRef<XTerminal | null>(null);

    useEffect(() => {
      const term = new XTerminal({
          cursorBlink: true,
          fontSize: 14,
          convertEol: true,
          theme: {
            background: "oklch(21.15% 0.012 254.09)",
          }
      });
      term.loadAddon(fitAddon);
      termRef.current = term;

      if (terminalRef.current) {
          term.open(terminalRef.current);
          fitAddon.fit();
      }

      const socket = new WebSocket('ws://localhost:4242/terminal');
      socketRef.current = socket;

      // When data comes from backend, write to terminal
      socket.addEventListener('message', (event) => {
          term.write(event.data);
      });

      socket.addEventListener('open', () => {
        setReconnectButtonVisible(false)
      })

      socket.addEventListener('close', () => {
        setReconnectButtonVisible(true)
      })

      // Send user keystrokes to backend
      term.onData((data) => {
          socket.send(data);
      });

      const handleResize = () => {
          if (term) {
              fitAddon.fit();
          }
      };

      window.addEventListener('resize', handleResize);

      return () => {
          socket.close();
          term.dispose();
          window.removeEventListener('resize', handleResize);
      };
    }, []);

    return  (
      <div className="card bg-base-300 border border-base-300">
        <div className="card-body p-4">
          <div ref={terminalRef} className="w-full h-full" />
        </div>
      </div>
    );
}

export const Terminal: React.FC = () => {
    const [key, setKey] = useState(0);
    const [showReconnectBtn, setShowReconnectBtn] = useState<boolean>(false);
    
    const reload = () => {
      setKey(prevKey => prevKey + 1);
    };

    return  (
      <div className="w-full flex flex-col gap-2">
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-2">
            <IoTerminalSharp size={32}/>
            <h1 className="text-2xl font-semibold">Terminal</h1>
          </div>
          {showReconnectBtn && (
            <button className="btn btn-info" onClick={reload}>Reconnect</button>
          )}
        </div>
        <TerminalComponent key={key} setReconnectButtonVisible={setShowReconnectBtn} />
      </div>
    );
};