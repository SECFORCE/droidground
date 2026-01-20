import { useState } from "react";
import { RESTManagerInstance } from "@client/api/rest";
import { CompanionAttackSurface } from "@server/utils/types";
import { GetAttackSurfaceRequest } from "@shared/api";
import { SubmitHandler, useForm } from "react-hook-form";
import toast from "react-hot-toast";
import { VscDebug } from "react-icons/vsc";

export const Debug: React.FC = () => {
  const [attackSurface, setAttackSurface] = useState<CompanionAttackSurface>();
  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<GetAttackSurfaceRequest>();

  const retrieveAttackSurface: SubmitHandler<GetAttackSurfaceRequest> = async data => {
    if (!data.debugToken) {
      return;
    }

    try {
      const res = await RESTManagerInstance.getAttackSurface(data.debugToken);
      setAttackSurface(res.data);
    } catch (e) {
      console.error(e);
      toast.error("Error while retrieving attack surface");
    }
  };

  return (
    <div className="w-full flex flex-col gap-2">
      <div className="flex gap-2 items-center mb-2">
        <VscDebug size={32} />
        <h1 className="text-2xl font-semibold select-none">Debug</h1>
      </div>
      <div className="card bg-base-300 border border-base-300">
        <div className="card-body p-4">
          <div className="card-title justify-between select-none">
            <h2>Attack Surface</h2>
          </div>
          <div className="flex gap-2">
            <form
              onSubmit={handleSubmit(retrieveAttackSurface)}
              className="flex flex-1 space-y-4 flex-col lg:flex-row lg:gap-4"
            >
              <input
                type="text"
                placeholder="Debug Token in server logs"
                className="input input-bordered w-full"
                {...register("debugToken", { required: true })}
              />
              {errors.debugToken && <p className="text-error text-sm">Debug Token is required.</p>}

              {/* Submit */}
              <div className="flex w-full lg:w-auto justify-end">
                <input className="btn btn-primary w-full" type="submit" value="Get Attack Surface" />
              </div>
            </form>
          </div>
          <div className="code-mockup hide-before">
            <pre className="text-accent text-wrap wrap-break-word break-all">
              <code> {JSON.stringify(attackSurface, null, 2)}</code>
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
};
