import { Route, Routes } from "react-router-dom";
import AssetsListPage from "./pages/AssetsListPage";
import AssetDetailPage from "./pages/AssetDetailPage";
import FindingDetailPage from "./pages/FindingDetailPage";
import ScanDetailPage from "./pages/ScanDetailPage";
import DastScanDetailPage from "./pages/DastScanDetailPage";
import NotFoundPage from "./pages/NotFoundPage";

export function AppRouter() {
  return (
    <Routes>
      <Route path="/" element={<AssetsListPage />} />
      <Route path="/assets/:assetId" element={<AssetDetailPage />} />
      <Route path="/findings/:findingId" element={<FindingDetailPage />} />
      <Route path="/scans/:scanId" element={<ScanDetailPage />} />
      <Route path="/dast/scans/:scanId" element={<DastScanDetailPage />} />
      <Route path="*" element={<NotFoundPage />} />
    </Routes>
  );
}
