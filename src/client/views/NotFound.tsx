import { BsAndroid2 } from "react-icons/bs";

export const NotFound: React.FC = () => {
  return (
    <div className="hero">
      <div className="hero-content text-center">
        <div className="max-w-md">
          <div className="flex items-center text-emerald-600">
            <h1 className="text-[16rem] leading-none select-none -mr-8 tstroke">4</h1>
            <BsAndroid2
              size={180}
              className="text-shadow-black text-shadow-lg z-20 stroke-black stroke-[0.5]"
              stroke="#000"
            />
            <h1 className="text-[16rem] leading-none select-none -ml-8 tstroke">4</h1>
          </div>
          <h1 className="mb-5 font-bold opacity-20 text-5xl">Not Found</h1>
          <a className="btn btn-info " href="/">
            Home
          </a>
        </div>
      </div>
    </div>
  );
};
