import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import Modal from "./Modal";
import Spinner from "./Spinner";
import { ApiError, createAsset } from "../lib/api";
import { qk } from "../lib/queries";

export default function AddAssetModal({
  open,
  onClose,
}: {
  open: boolean;
  onClose: () => void;
}) {
  const [repoUrl, setRepoUrl] = useState("");
  const [error, setError] = useState<string | null>(null);
  const qc = useQueryClient();
  const navigate = useNavigate();

  const mutation = useMutation({
    mutationFn: (url: string) => createAsset({ repo_url: url }),
    onSuccess: (asset) => {
      qc.invalidateQueries({ queryKey: qk.assets });
      setRepoUrl("");
      setError(null);
      onClose();
      navigate(`/assets/${asset.id}`);
    },
    onError: (e: unknown) => {
      if (e instanceof ApiError) {
        if (e.status === 409) {
          setError("Asset ja existe.");
          return;
        }
        setError(`Falha (${e.status}): ${e.message}`);
        return;
      }
      setError("Falha desconhecida ao criar asset.");
    },
  });

  const handleClose = () => {
    if (mutation.isPending) return;
    setError(null);
    setRepoUrl("");
    onClose();
  };

  return (
    <Modal open={open} onClose={handleClose} title="Adicionar asset">
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (!repoUrl.trim()) {
            setError("Informe a URL do repo.");
            return;
          }
          setError(null);
          mutation.mutate(repoUrl.trim());
        }}
        className="space-y-3"
      >
        <label className="block">
          <span className="text-sm text-slate-700">URL do repositorio</span>
          <input
            type="url"
            value={repoUrl}
            onChange={(e) => setRepoUrl(e.target.value)}
            placeholder="https://github.com/org/repo"
            className="mt-1 w-full rounded border border-slate-300 px-3 py-2 text-sm focus:border-cyan-500 focus:outline-none"
            disabled={mutation.isPending}
            autoFocus
          />
        </label>
        {error && <div className="text-sm text-red-700">{error}</div>}
        <div className="flex justify-end gap-2">
          <button
            type="button"
            onClick={handleClose}
            disabled={mutation.isPending}
            className="rounded px-3 py-1.5 text-sm text-slate-600 hover:bg-slate-100 disabled:opacity-50"
          >
            Cancelar
          </button>
          <button
            type="submit"
            disabled={mutation.isPending}
            className="inline-flex items-center gap-2 rounded-md bg-cyan-700 px-3 py-1.5 text-sm font-medium text-white hover:bg-cyan-800 disabled:opacity-50"
          >
            {mutation.isPending && <Spinner className="h-3 w-3" />}
            Adicionar
          </button>
        </div>
      </form>
    </Modal>
  );
}
