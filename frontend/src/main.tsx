import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter, Route, Routes } from 'react-router-dom'
import './index.css'
import App from './App.tsx'
import SubmitPage from './pages/SubmitPage.tsx'
import ReportPage from './pages/ReportPage.tsx'
import ReportsListPage from './pages/ReportsListPage.tsx'
import VerifyPage from './pages/VerifyPage.tsx'
import TrackerPage from './pages/TrackerPage.tsx'
import ReportFraudPage from './pages/ReportFraudPage.tsx'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter>
      <Routes>
        <Route element={<App />}>
          <Route index element={<SubmitPage />} />
          <Route path="tracker" element={<TrackerPage />} />
          <Route path="tracker/:id" element={<TrackerPage />} />
          <Route path="report-fraud" element={<ReportFraudPage />} />
          <Route path="reports" element={<ReportsListPage />} />
          <Route path="reports/:id" element={<ReportPage />} />
          <Route path="verify" element={<VerifyPage />} />
          <Route path="*" element={<SubmitPage />} />
        </Route>
      </Routes>
    </BrowserRouter>
  </StrictMode>,
)
