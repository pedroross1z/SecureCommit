import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import {
  ApiError,
  createDastMonitor,
  listDastMonitors,
  respiderDastMonitor,
  stopDastMonitor,
} from "../lib/api";
import { qk } from "../lib/queries";
import Modal from "./Modal";
import Spinner from "./Spinner";
import { formatDate } from "../lib/format";
import type { DastMonitorOut, DastMonitorStatus } from "../lib/types";

const URL_RE = /^https?:\/\/[^\s]+$/i;

const STATUS_CLASSES: Record<DastMonitorStatus, string> = {
  starting: "bg-amber-100 text-amber-800",
  running: "bg-emerald-100 text-emerald-800",
  stopped: "bg-slate-200 text-slate-700",
  failed: "bg-red-100 text-red-800",
};

const STATUS_LABELS: Record<DastMonitorStatus, string> = {
  starting: "iniciando",
  running: "ao vivo",
  stopped: "parado",
  failed: "falhou",
};


function MonitorStatusPill({ status }: { status: DastMonitorStatus }) {
  const active = status === "starting" || status === "running";
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded px-2 py-1 text-xs font-medium ${STATUS_CLASSES[status]}`}
    >
      {active && <Spinner className="h-3 w-3" />}
      {STATUS_LABELS[status]}
    </span>
  );
}


function NextPollCountdown({ monitor }: { monitor: DastMonitorOut }) {
  if (monitor.status !== "running" || !monitor.next_poll_at) return null;
  const next = new Date(monitor.next_poll_at).getTime();
  const now = Date.now();
  const diff = Math.max(0, Math.floor((next - now) / 1000));
  return (
    <span className="text-xs text-slate-500">
      próximo poll em {diff}s
    </span>
  );
}


function StartMonitorModal({
  open,
  onClose,
  assetId,
}: {
  open: boolean;
  onClose: () => void;
  assetId: string;
}) {
  const [url, setUrl] = useState("http://host.docker.internal:3000");
  const [interval, setInterval] = useState("60");
  const [allowPrivate, setAllowPrivate] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const qc = useQueryClient();

  const mutation = useMutation({
    mutationFn: () => {
      const options: Record<string, unknown> = {};
      if (allowPrivate) options.allow_private = true;
      return createDastMonitor({
        asset_id: assetId,
        target_url: url.trim(),
        poll_interval_s: Math.max(15, Math.min(3600, Number(interval) || 60)),
        options: Object.keys(options).length ? options : null,
      });
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.dastMonitors(assetId) });
      onClose();
    },
    onError: (e: unknown) => {
      if (e instanceof ApiError) setError(`Falha (${e.status}): ${e.message}`);
      else setError("Falha desconhecida");
    },
  });

  return (
    <Modal open={open} onClose={onClose} title="Iniciar monitor DAST contínuo">
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (!URL_RE.test(url.trim())) {
            setError("URL invalida — use http:// ou https://");
            return;
          }
          setError(null);
          mutation.mutate();
        }}
        className="space-y-4"
      >
        <label className="block">
          <span className="text-sm text-slate-700">URL alvo (app rodando)</span>
          <input
            type="url"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            className="mt-1 w-full rounded border border-slate-300 px-3 py-2 text-sm"
            disabled={mutation.isPending}
            autoFocus
          />
          <span className="text-xs text-slate-500">
            Alvo deve ser uma web app rodando (ex: Juice Shop em{" "}
            <code>http://host.docker.internal:3000</code>). Repositorio git nao
            e alvo DAST.
          </span>
        </label>
        <label className="block">
          <span className="text-sm text-slate-700">Intervalo de poll (s)</span>
          <input
            type="number"
            min={15}
            max={3600}
            value={interval}
            onChange={(e) => setInterval(e.target.value)}
            className="mt-1 w-32 rounded border border-slate-300 px-2 py-1 text-sm"
            disabled={mutation.isPending}
          />
          <span className="text-xs text-slate-500 ml-2">
            min 15s, max 3600s. Default 60s.
          </span>
        </label>
        <label className="flex items-start gap-2 text-xs text-slate-700">
          <input
            type="checkbox"
            checked={allowPrivate}
            onChange={(e) => setAllowPrivate(e.target.checked)}
            disabled={mutation.isPending}
            className="mt-0.5"
          />
          <span>
            Permitir alvo privado/loopback (precisa estar em{" "}
            <code>DAST_ALLOWLIST_HOSTS</code>).
          </span>
        </label>
        {error && <div className="text-sm text-red-700">{error}</div>}
        <div className="flex justify-end gap-2">
          <button
            type="button"
            onClick={onClose}
            disabled={mutation.isPending}
            className="rounded px-3 py-1.5 text-sm text-slate-600 hover:bg-slate-100 disabled:opacity-50"
          >
            Cancelar
          </button>
          <button
            type="submit"
            disabled={mutation.isPending}
            className="inline-flex items-center gap-2 rounded-md bg-emerald-700 px-3 py-1.5 text-sm font-medium text-white hover:bg-emerald-800 disabled:opacity-50"
          >
            {mutation.isPending && <Spinner className="h-3 w-3" />}
            Iniciar monitor
          </button>
        </div>
      </form>
    </Modal>
  );
}


export default function DastMonitorCard({ assetId }: { assetId: string }) {
  const [modalOpen, setModalOpen] = useState(false);
  const qc = useQueryClient();

  const query = useQuery({
    queryKey: qk.dastMonitors(assetId),
    queryFn: () => listDastMonitors(assetId),
    refetchInterval: 5_000,
  });

  const stopMutation = useMutation({
    mutationFn: (id: string) => stopDastMonitor(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.dastMonitors(assetId) }),
  });

  const respiderMutation = useMutation({
    mutationFn: (id: string) => respiderDastMonitor(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.dastMonitors(assetId) }),
  });

  const monitors = query.data ?? [];
  const active = monitors.filter(
    (m) => m.status === "running" || m.status === "starting",
  );

  return (
    <div className="rounded-lg border border-emerald-200 bg-emerald-50/50 p-4 space-y-3">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-semibold text-emerald-900">
            Monitor contínuo (ZAP ao vivo)
          </h3>
          <p className="text-xs text-emerald-800/80">
            Spider + passive scan rodando continuamente. Novas vulnerabilidades
            aparecem conforme a app muda.
          </p>
        </div>
        {active.length === 0 && (
          <button
            onClick={() => setModalOpen(true)}
            className="inline-flex items-center gap-2 rounded-md bg-emerald-700 px-3 py-1.5 text-sm font-medium text-white hover:bg-emerald-800"
          >
            + Iniciar monitor
          </button>
        )}
      </div>

      {monitors.length === 0 && (
        <p className="text-sm text-slate-500 italic">
          Nenhum monitor ainda. Inicie um para ter DAST contínuo contra uma
          app web rodando.
        </p>
      )}

      {monitors.map((m) => (
        <div
          key={m.id}
          className="rounded border border-slate-200 bg-white p-3 space-y-2 text-sm"
        >
          <div className="flex items-center justify-between flex-wrap gap-2">
            <div className="flex items-center gap-2 flex-wrap">
              <MonitorStatusPill status={m.status} />
              <span className="font-mono text-xs text-slate-700 break-all">
                {m.target_url}
              </span>
            </div>
            <div className="flex items-center gap-2">
              {m.status === "running" && (
                <>
                  <button
                    onClick={() => respiderMutation.mutate(m.id)}
                    disabled={respiderMutation.isPending}
                    className="rounded border border-slate-300 bg-white px-2 py-1 text-xs text-slate-700 hover:bg-slate-50 disabled:opacity-50"
                    title="Re-dispara spider para descobrir rotas novas"
                  >
                    Re-spider
                  </button>
                  <button
                    onClick={() => stopMutation.mutate(m.id)}
                    disabled={stopMutation.isPending}
                    className="rounded border border-red-300 bg-white px-2 py-1 text-xs text-red-700 hover:bg-red-50 disabled:opacity-50"
                  >
                    Parar
                  </button>
                </>
              )}
              {(m.status === "stopped" || m.status === "failed") &&
                m.alerts_total > 0 && (
                  <Link
                    to={`/dast/monitors/${m.id}/findings`}
                    className="text-xs text-cyan-700 hover:underline"
                  >
                    Ver findings →
                  </Link>
                )}
            </div>
          </div>
          <dl className="grid grid-cols-2 md:grid-cols-4 gap-x-4 gap-y-1 text-xs">
            <div>
              <dt className="text-slate-500">Alertas</dt>
              <dd className="font-semibold">{m.alerts_total}</dd>
            </div>
            <div>
              <dt className="text-slate-500">Polls</dt>
              <dd>{m.polls_total}</dd>
            </div>
            <div>
              <dt className="text-slate-500">Intervalo</dt>
              <dd>{m.poll_interval_s}s</dd>
            </div>
            <div>
              <dt className="text-slate-500">Iniciado</dt>
              <dd>{formatDate(m.started_at)}</dd>
            </div>
            <div className="col-span-2 md:col-span-4">
              <NextPollCountdown monitor={m} />
            </div>
          </dl>
          {m.last_error && (
            <div className="text-xs text-red-700 border-t border-slate-100 pt-2">
              Erro: {m.last_error}
            </div>
          )}
          {m.alerts_total > 0 && (
            <Link
              to={`/assets/${m.asset_id}?tab=findings`}
              className="text-xs text-cyan-700 hover:underline"
            >
              Ver {m.alerts_total} findings na tabela do asset →
            </Link>
          )}
        </div>
      ))}

      <StartMonitorModal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        assetId={assetId}
      />
    </div>
  );
}
