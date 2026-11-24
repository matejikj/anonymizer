import { ErrorBoundary } from './components/ui/ErrorBoundary.tsx'
import { AppShell } from './features/workspace/AppShell.tsx'
import { resetApplication } from './app/sessionLifecycleCoordinator.ts'
import { DETECTION_WORKER_URL } from './workers/urls.ts'
import { createExportWorker } from './app/exportWorkerClient.ts'
import { createPcapExportWorker } from './pcap/export/pcapExportWorkerClient.ts'
import './styles/app.css'

// Keep Worker modules in the production graph (ARCHITECTURE §5.3).
void DETECTION_WORKER_URL
void createExportWorker
void createPcapExportWorker

function App() {
  return (
    <ErrorBoundary
      onReset={() => {
        resetApplication()
      }}
    >
      <AppShell />
    </ErrorBoundary>
  )
}

export default App
