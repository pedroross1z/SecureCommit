import { Link } from "react-router-dom";

export default function NotFoundPage() {
  return (
    <div className="text-center py-16">
      <h1 className="text-3xl font-semibold text-slate-700">404</h1>
      <p className="text-slate-500 mt-2">Pagina nao encontrada.</p>
      <Link to="/" className="mt-4 inline-block text-cyan-700 hover:underline">
        Voltar para assets
      </Link>
    </div>
  );
}
