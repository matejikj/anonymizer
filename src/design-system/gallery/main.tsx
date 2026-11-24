import { StrictMode, useState } from 'react'
import { createRoot } from 'react-dom/client'
import '../../styles/app.css'
import {
  Badge,
  Button,
  Card,
  Checkbox,
  CommandBar,
  DataSurface,
  EmptyState,
  ErrorState,
  ExportSummary,
  FileRow,
  GlassPanel,
  IconButton,
  LoadingState,
  Progress,
  RaisedPanel,
  SearchField,
  SegmentedControl,
  StatusSummary,
  Switch,
  Tabs,
  TextInput,
  Tooltip,
} from '../index.ts'
import { StatusChip } from '../../components/ui/StatusChip.tsx'
import { IconHelp, IconExport, IconLock } from '../../components/ui/icons.tsx'

function GalleryApp() {
  const [seg, setSeg] = useState('a')
  const [tab, setTab] = useState('one')
  const [theme, setTheme] = useState<'light' | 'dark'>('light')

  return (
    <div className="app-shell" data-density="comfortable" data-design="forensic-bench" data-theme={theme}>
      <main
        id="main"
        className="app-main"
        data-testid="design-system-gallery"
        style={{ width: 'min(960px, 100%)', margin: '0 auto', padding: '24px' }}
      >
        <header style={{ display: 'flex', gap: 12, alignItems: 'center', marginBottom: 24 }}>
          <h1 className="type-page-title">Design system gallery</h1>
          <Button
            variant="secondary"
            data-testid="gallery-theme-toggle"
            onClick={() => {
              const next = theme === 'light' ? 'dark' : 'light'
              setTheme(next)
              document.documentElement.setAttribute('data-theme', next)
            }}
          >
            Theme: {theme}
          </Button>
        </header>

        <section data-testid="gallery-bench-chrome" aria-label="Bench chrome" style={{ marginBottom: 24 }}>
          <h2 className="type-section-title">Bench chrome</h2>
          <p className="type-meta" style={{ marginBottom: 12 }}>
            Forensic Bench: matte menubar, flat controls, 2px selection rail.
          </p>
          <div className="gallery-bench-menubar" data-testid="gallery-bench-menubar">
            <div className="gallery-bench-menubar__brand">
              <span className="type-section-title">Anonymizer</span>
              <span className="gallery-bench-menubar__privacy" title="Local-only">
                <IconLock size={16} />
              </span>
            </div>
            <div className="gallery-bench-menubar__stepper" aria-hidden="true">
              <span className="gallery-bench-dot gallery-bench-dot--active" />
              <span className="gallery-bench-dot" />
              <span className="gallery-bench-dot" />
            </div>
            <div className="gallery-bench-menubar__actions">
              <IconButton label="Help">
                <IconHelp size={18} />
              </IconButton>
              <Button variant="ghost">Cancel</Button>
              <Button variant="primary">Export</Button>
            </div>
          </div>
          <DataSurface style={{ marginTop: 12, padding: 0 }} data-testid="gallery-bench-selection">
            <div className="gallery-bench-row">Idle occurrence</div>
            <div className="gallery-bench-row gallery-bench-row--selected" aria-selected="true">
              Selected (2px rail)
            </div>
            <div className="gallery-bench-row gallery-bench-row--hover">Hover wash</div>
          </DataSurface>
        </section>

        <section data-testid="gallery-buttons" aria-label="Buttons">
          <h2 className="type-section-title">Buttons</h2>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
            <Button variant="primary">Primary</Button>
            <Button variant="secondary">Secondary</Button>
            <Button variant="ghost">Ghost</Button>
            <Button variant="quiet">Quiet</Button>
            <Button variant="destructive">Destructive</Button>
            <Button variant="primary" busy>
              Busy
            </Button>
            <Button variant="secondary" disabled>
              Disabled
            </Button>
            <IconButton label="Help">
              <IconHelp size={18} />
            </IconButton>
          </div>
        </section>

        <section data-testid="gallery-fields" aria-label="Fields" style={{ marginTop: 24 }}>
          <h2 className="type-section-title">Fields</h2>
          <TextInput id="g-name" label="Name" defaultValue="sample" />
          <SearchField id="g-search" label="Search" placeholder="Hledat…" />
          <Checkbox id="g-check" label="Checkbox" defaultChecked />
          <Switch id="g-switch" label="Switch" />
        </section>

        <section data-testid="gallery-controls" aria-label="Controls" style={{ marginTop: 24 }}>
          <h2 className="type-section-title">Controls</h2>
          <SegmentedControl
            label="Segmented"
            value={seg}
            onChange={setSeg}
            options={[
              { id: 'a', label: 'A' },
              { id: 'b', label: 'B' },
              { id: 'c', label: 'C', disabled: true },
            ]}
          />
          <Tabs
            label="Tabs"
            value={tab}
            onChange={setTab}
            tabs={[
              { id: 'one', label: 'One' },
              { id: 'two', label: 'Two' },
            ]}
          />
          <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
            <Badge tone="safe">Safe</Badge>
            <Badge tone="warn">Warn</Badge>
            <Badge tone="blocked">Blocked</Badge>
            <StatusChip tone="ok" label="OK" />
            <StatusChip tone="warn" label="Warn" />
            <Tooltip label="Export help">
              <IconButton label="Export tip">
                <IconExport size={18} />
              </IconButton>
            </Tooltip>
          </div>
          <Progress value={42} max={100} label="Progress 42%" />
        </section>

        <section data-testid="gallery-surfaces" aria-label="Surfaces" style={{ marginTop: 24 }}>
          <h2 className="type-section-title">Surfaces</h2>
          <GlassPanel style={{ padding: 16, marginBottom: 12 }}>Glass panel</GlassPanel>
          <RaisedPanel style={{ padding: 16, marginBottom: 12 }}>Raised panel</RaisedPanel>
          <DataSurface style={{ padding: 16, marginBottom: 12 }} data-testid="gallery-data-surface">
            Data surface (no blur)
          </DataSurface>
          <Card>Card content</Card>
        </section>

        <section data-testid="gallery-patterns" aria-label="Patterns" style={{ marginTop: 24 }}>
          <h2 className="type-section-title">Patterns</h2>
          <CommandBar
            testId="gallery-command-bar"
            context={<span>file.log</span>}
            status={
              <StatusSummary>
                <StatusChip tone="ok" label="Safe" />
              </StatusSummary>
            }
            primary={<Button variant="primary">Export</Button>}
          />
          <FileRow name="capture.pcap" meta="1.2 MiB" />
          <EmptyState title="Empty" body="Nothing here yet." />
          <ErrorState title="Error" body="Something failed." />
          <LoadingState title="Loading" body="Please wait…" />
          <ExportSummary>
            <div className="ds-export-summary__section">What will be exported</div>
            <div className="ds-export-summary__section">Security notes</div>
          </ExportSummary>
        </section>
      </main>
    </div>
  )
}

document.documentElement.setAttribute('data-theme', 'light')
createRoot(document.getElementById('gallery-root')!).render(
  <StrictMode>
    <GalleryApp />
  </StrictMode>,
)
