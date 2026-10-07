import ReactDiffViewer from "react-diff-viewer-continued";

/**
 * Renderiza um unified diff. O componente `react-diff-viewer-continued` espera
 * dois arquivos (old/new), entao aqui parseamos as linhas +/- do patch e
 * reconstruimos as duas versoes de forma simplificada.
 */
function parseUnifiedDiff(diff: string): { oldText: string; newText: string } {
  const lines = diff.split("\n");
  const oldLines: string[] = [];
  const newLines: string[] = [];
  let inHunk = false;
  for (const line of lines) {
    if (line.startsWith("@@")) {
      inHunk = true;
      continue;
    }
    if (!inHunk) continue;
    if (line.startsWith("---") || line.startsWith("+++")) continue;
    if (line.startsWith("+")) {
      newLines.push(line.slice(1));
    } else if (line.startsWith("-")) {
      oldLines.push(line.slice(1));
    } else {
      oldLines.push(line.startsWith(" ") ? line.slice(1) : line);
      newLines.push(line.startsWith(" ") ? line.slice(1) : line);
    }
  }
  return { oldText: oldLines.join("\n"), newText: newLines.join("\n") };
}

export default function DiffViewer({ diff }: { diff: string | null | undefined }) {
  if (!diff || !diff.trim()) {
    return (
      <div className="text-sm text-slate-500 italic">
        Sem patch disponivel (verifique a explicacao acima).
      </div>
    );
  }
  const { oldText, newText } = parseUnifiedDiff(diff);
  return (
    <div className="border border-slate-200 rounded overflow-hidden text-xs">
      <ReactDiffViewer
        oldValue={oldText}
        newValue={newText}
        splitView={false}
        hideLineNumbers={false}
        useDarkTheme={false}
      />
    </div>
  );
}
