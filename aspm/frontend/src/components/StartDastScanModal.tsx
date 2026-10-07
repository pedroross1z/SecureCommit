import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import Modal from "./Modal";
import Spinner from "./Spinner";
import {
  ApiError,
  createDastScan,
  listDastProfiles,
} from "../lib/api";
import { STALE_LIST, qk } from "../lib/queries";
import type { DastProfileName } from "../lib/types";

const URL_RE = /^https?:\/\/[^\s]+$/i;

export default function StartDastScanModal({
  open,
  onClose,
  assetId,
  defaultUrl,
}: {
  open: boolean;
  onClose: () => void;
  assetId: string;
  defaultUrl?: string | null;
}) {
  const [targetUrl, setTargetUrl] = useState(defaultUrl ?? "");
  const [profile, setProfile] = useState<DastProfileName>("baseline");
  const [authorized, setAuthorized] = useState(false);
  const [allowPrivate, setAllowPrivate] = useState(false);
  const [timeoutS, setTimeoutS] = useState<string>("");
  const [error, setError] = useState<string | null>(null);

  const qc = useQueryClient();
  const navigate = useNavigate();

  const profilesQuery = useQuery({
    queryKey: qk.dastProfiles,
    queryFn: listDastProfiles,
    staleTime: STALE_LIST,
  });

  const selected = useMemo(
    () => profilesQuery.data?.find((p) => p.name === profile) ?? null,
    [profilesQuery.data, profile],
  );

  useEffect(() => {
    if (open) {
      setTargetUrl(defaultUrl ?? "");
      setProfile("baseline");
      setAuthorized(false);
      setAllowPrivate(false);
      setTimeoutS("");
      setError(null);
    }
  }, [open, defaultUrl]);

  const mutation = useMutation({
    mutationFn: () => {
      const options: Record<string, unknown> = {};
      if (allowPrivate) options.allow_private = true;
      const n = Number(timeoutS);
      if (timeoutS && !Number.isNaN(n) && n > 0) options.timeout_s = n;
      return createDastScan({
        asset_id: assetId,
        target_url: targetUrl.trim(),
        profile,
        authorized: selected?.requires_authorization ? authorized : false,
        options: Object.keys(options).length ? options : null,
      });
    },
    onSuccess: (scan) => {
      qc.invalidateQueries({ queryKey: qk.dastScans(assetId) });
      qc.invalidateQueries({ queryKey: qk.dastScans() });
      onClose();
      navigate(`/dast/scans/${scan.id}`);
    },
    onError: (e: unknown) => {
      if (e instanceof ApiError) {
        setError(`Falha (${e.status}): ${e.message}`);
        return;
      }
      setError("Falha desconhecida ao criar scan DAST.");
    },
  });

  const handleClose = () => {
    if (mutation.isPending) return;
    onClose();
  };

  const requiresAuth = selected?.requires_authorization ?? false;
  const canSubmit =
    !mutation.isPending &&
    URL_RE.test(targetUrl.trim()) &&
    (!requiresAuth || authorized);

  return (
    <Modal open={open} onClose={handleClose} title="Novo scan DAST (OWASP ZAP)">
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (!URL_RE.test(targetUrl.trim())) {
            setError("URL invalida — use http:// ou https://");
            return;
          }
          if (requiresAuth && !authorized) {
            setError(
              "Perfil requer autorizacao explicita para enviar payloads ofensivos.",
            );
            return;
          }
          setError(null);
          mutation.mutate();
        }}
        className="space-y-4"
      >
        <label className="block">
          <span className="text-sm text-slate-700">URL de destino</span>
          <input
            type="url"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            placeholder="https://alvo-autorizado.exemplo"
            className="mt-1 w-full rounded border border-slate-300 px-3 py-2 text-sm focus:border-cyan-500 focus:outline-none"
            disabled={mutation.isPending}
            autoFocus
          />
          <span className="text-xs text-slate-500">
            Loopback e redes privadas sao bloqueados por default (SSRF guard).
          </span>
        </label>

        <label className="block">
          <span className="text-sm text-slate-700">Perfil</span>
          <select
            value={profile}
            onChange={(e) => setProfile(e.target.value as DastProfileName)}
            className="mt-1 w-full rounded border border-slate-300 px-3 py-2 text-sm"
            disabled={mutation.isPending || profilesQuery.isPending}
          >
            {(profilesQuery.data ?? []).map((p) => (
              <option key={p.name} value={p.name}>
                {p.name}
                {p.requires_authorization ? " — requer autorizacao" : ""}
              </option>
            ))}
          </select>
          {selected && (
            <span className="text-xs text-slate-500 block mt-1">
              {selected.description}
            </span>
          )}
        </label>

        {requiresAuth && (
          <div className="rounded border border-amber-300 bg-amber-50 p-3 text-xs text-amber-900 space-y-2">
            <div className="font-semibold">
              Atencao: este perfil envia payloads ofensivos.
            </div>
            <div>
              Rode apenas em ambientes de homologacao, laboratorio ou alvos
              com autorizacao expressa. Scans ativos podem corromper dados.
            </div>
            <label className="flex items-start gap-2 pt-1">
              <input
                type="checkbox"
                checked={authorized}
                onChange={(e) => setAuthorized(e.target.checked)}
                disabled={mutation.isPending}
                className="mt-0.5"
              />
              <span>
                Confirmo que tenho autorizacao para executar scan ativo contra
                este alvo.
              </span>
            </label>
          </div>
        )}

        <details className="rounded border border-slate-200 bg-slate-50 p-3">
          <summary className="text-xs text-slate-600 cursor-pointer">
            Opcoes avancadas
          </summary>
          <div className="mt-3 space-y-3">
            <label className="flex items-start gap-2 text-xs text-slate-700">
              <input
                type="checkbox"
                checked={allowPrivate}
                onChange={(e) => setAllowPrivate(e.target.checked)}
                disabled={mutation.isPending}
                className="mt-0.5"
              />
              <span>
                Permitir alvo privado/loopback (host deve estar em{" "}
                <code>DAST_ALLOWLIST_HOSTS</code>).
              </span>
            </label>
            <label className="block text-xs text-slate-700">
              <span>Timeout (s)</span>
              <input
                type="number"
                min={1}
                max={selected?.max_timeout_s ?? 7200}
                value={timeoutS}
                onChange={(e) => setTimeoutS(e.target.value)}
                placeholder={
                  selected ? String(selected.default_timeout_s) : "default"
                }
                className="mt-1 w-32 rounded border border-slate-300 px-2 py-1"
                disabled={mutation.isPending}
              />
              {selected && (
                <span className="text-slate-500 ml-2">
                  default {selected.default_timeout_s}s, max{" "}
                  {selected.max_timeout_s}s
                </span>
              )}
            </label>
          </div>
        </details>

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
            disabled={!canSubmit}
            className="inline-flex items-center gap-2 rounded-md bg-cyan-700 px-3 py-1.5 text-sm font-medium text-white hover:bg-cyan-800 disabled:opacity-50"
          >
            {mutation.isPending && <Spinner className="h-3 w-3" />}
            Iniciar scan
          </button>
        </div>
      </form>
    </Modal>
  );
}
