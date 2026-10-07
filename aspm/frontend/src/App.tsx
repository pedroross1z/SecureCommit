import { Link } from "react-router-dom";
import { AppRouter } from "./router";

export default function App() {
  return (
    <div className="min-h-screen bg-slate-50 text-slate-900">
      <header className="border-b border-slate-200 bg-white">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center gap-4">
          <Link to="/" className="flex items-center gap-3 text-xl font-semibold text-slate-900">
            <img src="/logo.png" alt="Secure Commit" className="h-8 w-8" />
            Secure Commit
          </Link>
          <span className="text-sm text-slate-500">
            Application Security Posture Management
          </span>
        </div>
      </header>
      <main className="max-w-7xl mx-auto px-6 py-8">
        <AppRouter />
      </main>
    </div>
  );
}
