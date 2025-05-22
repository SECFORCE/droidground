interface IModalProps {
  dialogRef: React.RefObject<HTMLDialogElement | null>;
  title: string;
  description: string;
  onConfirm: () => void;
}

export const ConfirmModal: React.FC<IModalProps> = ({ dialogRef, title, description, onConfirm }) => {
  return (
    <dialog ref={dialogRef} className="modal">
      <div className="modal-box">
        <h3 className="font-bold text-lg">{title}</h3>
        <p className="py-4">{description}</p>
        <div className="modal-action">
          <form method="dialog" className="flex gap-2">
            {/* if there is a button in form, it will close the modal */}
            <button className="btn btn-error">Close</button>
            <button className="btn btn-success" onClick={onConfirm}>
              Confirm
            </button>
          </form>
        </div>
      </div>
      <form method="dialog" className="modal-backdrop">
        <button>close</button>
      </form>
    </dialog>
  );
};
