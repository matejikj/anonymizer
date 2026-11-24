import { cs } from '../../i18n/cs.ts'
import { usePcapStore } from './pcapStore.ts'
import { getPcapSession, findPacketIndexByNumber, getPacketCount } from './pcapSession.ts'
import { refreshPcapFilter } from './pcapLoadController.ts'
import { levelDisplayName } from '../profile/pcapAnonymizationLevel'
import type { PcapAnonymizationLevel } from '../profile/pcapAnonymizationLevel'
import { DEFAULT_PCAP_LEVEL } from '../profile/presets.ts'
import { formatBytes, formatPacketCount, protocolLabel } from './formatters.ts'
import { getPcapCoverageViewModel } from './getPcapCoverageViewModel.ts'
import { buildVoipObservability, formatVoipObservabilityLines } from '../coverage/voipObservability.ts'
import { useAppStore } from '../../app/store.ts'
import { SharedEntityList } from '../../features/correlation-workspace/CorrelationWorkspacePanels.tsx'
import { isMultiSourceCorrelationReview } from '../../correlation/correlationReviewModel.ts'
import { Button, IconButton, StatusGlyph, type StatusGlyphKind } from '../../design-system/index.ts'
import { IconClose } from '../../components/ui/icons.tsx'
import { PcapVerdictDetails } from './PcapVerdictDetails.tsx'
import { AnonymizationOutcomePanel } from './AnonymizationOutcomePanel.tsx'
import { getAnonymizationOutcome } from './getAnonymizationOutcome.ts'
import type { PcapProtocolCoverageRow } from '../coverage/pcapCoverageViewModel.ts'

function levelLabel(level: PcapAnonymizationLevel): string {
  const name = levelDisplayName(level)
  return level === DEFAULT_PCAP_LEVEL
    ? `${name} · ${cs.pcap.presets.defaultPresetBadge}`
    : name
}

export function PcapInspector({ dock = false }: { readonly dock?: boolean }) {
  const inspectorOpen = usePcapStore((s) => s.inspectorOpen)
  const setInspectorOpen = usePcapStore((s) => s.setInspectorOpen)
  const inspectorTab = usePcapStore((s) => s.inspectorTab)
  const setInspectorTab = usePcapStore((s) => s.setInspectorTab)
  const epoch = usePcapStore((s) => s.sessionEpoch)
  const phase = useAppStore((s) => s.phase)
  const session = epoch >= 0 ? getPcapSession() : null
  const showSharedTab = phase === 'correlation-review' && isMultiSourceCorrelationReview()
  const tabs = showSharedTab
    ? (['overview', 'entities', 'coverage', 'profile', 'shared'] as const)
    : (['overview', 'entities', 'coverage', 'profile'] as const)

  if (!inspectorOpen) {
    if (dock) return null
    return (
      <button
        type="button"
        className="pcap-inspector-toggle"
        data-testid="pcap-inspector-open"
        onClick={() => setInspectorOpen(true)}
      >
        {cs.pcap.inspector.open}
      </button>
    )
  }

  return (
    <aside
      className={`pcap-inspector surface-raised${dock ? ' pcap-inspector--dock' : ''}`}
      data-testid="pcap-inspector"
      aria-label={cs.pcap.inspector.label}
    >
      <header className="pcap-inspector__header">
        <h2>{cs.pcap.inspector.label}</h2>
        <IconButton
          tiny
          label={cs.pcap.inspector.close}
          onClick={() => setInspectorOpen(false)}
        >
          <IconClose size={16} />
        </IconButton>
      </header>
      <div className="pcap-inspector__tabs" role="tablist">
        {tabs.map((tab) => (
          <button
            key={tab}
            type="button"
            role="tab"
            aria-selected={inspectorTab === tab}
            className={inspectorTab === tab ? 'is-active' : ''}
            data-testid={`pcap-inspector-tab-${tab}`}
            onClick={() => setInspectorTab(tab)}
          >
            {cs.pcap.inspector.tabs[tab]}
          </button>
        ))}
      </div>
      <div className="pcap-inspector__body" role="tabpanel">
        {!session ? (
          <p>{cs.pcap.inspector.empty}</p>
        ) : inspectorTab === 'overview' ? (
          <OverviewTab />
        ) : inspectorTab === 'entities' ? (
          <EntitiesTab />
        ) : inspectorTab === 'coverage' ? (
          <CoverageTab />
        ) : inspectorTab === 'shared' && showSharedTab ? (
          <SharedEntityList embedded />
        ) : (
          <ProfileTab />
        )}
      </div>
    </aside>
  )
}

function overviewVerdictKind(exportLooksSafe: boolean, canExport: boolean): StatusGlyphKind {
  if (exportLooksSafe) return 'ok'
  if (canExport) return 'warn'
  return 'blocked'
}

function coverageVerdictKind(row: PcapProtocolCoverageRow): StatusGlyphKind {
  if (row.layerKind === 'sanitizer') return 'sanitizer'
  if (row.dominantUiStatus === 'covered') return 'ok'
  return 'warn'
}

function OverviewTab() {
  const session = getPcapSession()!
  const vm = getPcapCoverageViewModel()!
  const s = vm.summary
  const setInspectorTab = usePcapStore((store) => store.setInspectorTab)
  const voip = buildVoipObservability({
    unifiedCoverage: session.unifiedCoverage,
    packetDiscovery: session.packetDiscovery,
    analysis: session.analysis,
  })
  const voipLines = formatVoipObservabilityLines(voip, {
    line: (key, params) => {
      switch (key) {
        case 'sipMessages':
          return cs.pcap.inspector.voipSipMessages.replace('{n}', String(params.n))
        case 'dialogs':
          return cs.pcap.inspector.voipDialogs.replace('{n}', String(params.n))
        case 'mediaFlows':
          return cs.pcap.inspector.voipMediaFlows.replace('{n}', String(params.n))
        case 'mediaDropped':
          return cs.pcap.inspector.voipMediaDropped
            .replace('{rtp}', String(params.rtp))
            .replace('{rtcp}', String(params.rtcp))
        case 'mediaStripped':
          return cs.pcap.inspector.voipMediaStripped
            .replace('{rtp}', String(params.rtp))
            .replace('{rtcp}', String(params.rtcp))
        case 'mediaPreservedUnsafe':
          return cs.pcap.inspector.voipMediaPreservedUnsafe.replace('{n}', String(params.n))
        case 'encrypted':
          return cs.pcap.inspector.voipEncrypted.replace('{n}', String(params.n))
        case 'reassembly':
          return cs.pcap.inspector.voipReassembly.replace('{n}', String(params.n))
        case 'incomplete':
          return cs.pcap.inspector.voipIncomplete.replace('{n}', String(params.n))
        default:
          return ''
      }
    },
  })
  const hasVoip = voip.sipPacketCount > 0 || voip.mediaFlowCount > 0 || voip.encryptedCount > 0
  const outcome = getAnonymizationOutcome()
  return (
    <div className="pcap-overview" data-plan-revision={vm.planRevision} data-testid="pcap-overview">
      {outcome ? (
        <AnonymizationOutcomePanel
          outcome={outcome}
          className="pcap-overview__outcome"
          testId="pcap-overview-outcome"
          announceLive={false}
        />
      ) : null}
      <PcapVerdictDetails
        className="pcap-overview__verdict"
        testId="pcap-overview-verdict"
        primaryVerdict={s.primaryVerdict}
        reasons={s.reasons}
        glyphKind={overviewVerdictKind(s.exportLooksSafe, s.canExport)}
      >
        {s.primaryAction === 'inspect' ? (
          <Button
            variant="secondary"
            data-testid="pcap-overview-open-coverage"
            onClick={() => setInspectorTab('coverage')}
          >
            {cs.pcap.coverageUx.openCoverage}
          </Button>
        ) : null}
        <div className="pcap-overview__detail-sections">
          <p
            className="pcap-overview__gate"
            data-testid="pcap-overview-gate-badge"
            data-gate-badge={s.gateBadge ?? 'none'}
          >
            {s.gateBadgeLabel}
          </p>
          {(s.preExportSummaries ?? []).map((bucket) => (
            <div key={bucket.id} data-testid={`pcap-overview-summary-${bucket.id}`}>
              <h3>{bucket.title}</h3>
              <p>{bucket.body}</p>
            </div>
          ))}
          <h3>{cs.pcap.coverageUx.residualRiskTitle}</h3>
          <ul className="pcap-overview__residual-risks" data-testid="pcap-overview-residual-risks">
            {(s.residualRiskLabels ?? []).map((label) => (
              <li key={label}>{label}</li>
            ))}
          </ul>
          <p className="pcap-overview__residual" data-testid="pcap-overview-residual-note">
            {s.residualNote ?? cs.pcap.coverageUx.residualNote}
          </p>
          {hasVoip ? (
            <>
              <h3>{cs.pcap.inspector.voipSummaryTitle}</h3>
              <ul className="pcap-overview__voip" data-testid="pcap-voip-summary">
                {voipLines.map((line) => (
                  <li key={line}>{line}</li>
                ))}
              </ul>
            </>
          ) : null}
          <p className="pcap-overview__never-safe">{cs.pcap.inspector.neverFullySafe}</p>
        </div>
      </PcapVerdictDetails>
    </div>
  )
}

function EntitiesTab() {
  const session = getPcapSession()!
  const categoryFilter = usePcapStore((s) => s.entityCategoryFilter)
  const setCategoryFilter = usePcapStore((s) => s.setEntityCategoryFilter)
  const query = usePcapStore((s) => s.entityQuery)
  const setQuery = usePcapStore((s) => s.setEntityQuery)
  const setSelectedPacketIndex = usePcapStore((s) => s.setSelectedPacketIndex)
  const setFilter = usePcapStore((s) => s.setFilter)
  const setInspectorTab = usePcapStore((s) => s.setInspectorTab)

  const entities = (session.analysis?.entities ?? []).filter((e) => {
    if (categoryFilter !== 'all' && e.category !== categoryFilter) return false
    if (query && !e.value.toLowerCase().includes(query.toLowerCase()) && !e.key.includes(query)) {
      return false
    }
    return true
  })

  // Cap list for UI responsiveness
  const page = entities.slice(0, 200)

  const categories = Array.from(new Set((session.analysis?.entities ?? []).map((e) => e.category))).sort()

  const goToEntity = (key: string, firstPacket: number) => {
    setFilter({ entityKey: key })
    queueMicrotask(() => {
      refreshPcapFilter()
      const idx = findPacketIndexByNumber(firstPacket)
      if (idx >= 0) setSelectedPacketIndex(idx)
    })
  }

  const navigateOccurrence = (direction: 1 | -1) => {
    const store = usePcapStore.getState()
    const indices = store.filteredIndices
    if (indices.length === 0) return
    const pos = indices.indexOf(store.selectedPacketIndex)
    const next = Math.max(0, Math.min(indices.length - 1, (pos < 0 ? 0 : pos) + direction))
    setSelectedPacketIndex(indices[next]!)
  }

  return (
    <div className="pcap-entities">
      <div className="pcap-entities__controls">
        <label>
          <span className="visually-hidden">{cs.pcap.inspector.entityCategory}</span>
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            data-testid="pcap-entity-category"
          >
            <option value="all">{cs.pcap.inspector.allCategories}</option>
            {categories.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span className="visually-hidden">{cs.pcap.inspector.entitySearch}</span>
          <input
            type="search"
            value={query}
            placeholder={cs.pcap.inspector.entitySearch}
            onChange={(e) => setQuery(e.target.value)}
            data-testid="pcap-entity-search"
          />
        </label>
      </div>
      <div className="pcap-entities__nav">
        <Button variant="ghost" onClick={() => navigateOccurrence(-1)}>
          {cs.pcap.inspector.prevOccurrence}
        </Button>
        <Button variant="ghost" onClick={() => navigateOccurrence(1)}>
          {cs.pcap.inspector.nextOccurrence}
        </Button>
        <Button
          variant="ghost"
          onClick={() => {
            setFilter({ entityKey: '' })
            queueMicrotask(() => refreshPcapFilter())
            setInspectorTab('entities')
          }}
        >
          {cs.pcap.inspector.clearEntityFilter}
        </Button>
      </div>
      <ul className="pcap-entities__list" data-testid="pcap-entity-list">
        {page.map((e) => (
          <li key={e.key}>
            <button type="button" className="pcap-entity-item" onClick={() => goToEntity(e.key, e.firstPacket)}>
              <span className="pcap-entity-item__cat">{e.category}</span>
              <span className="pcap-entity-item__val">{maskEntity(e.value)}</span>
              <span className="pcap-entity-item__meta">
                #{e.firstPacket} · ×{e.count}
              </span>
            </button>
          </li>
        ))}
      </ul>
      {entities.length > 200 ? (
        <p className="pcap-entities__more">
          {cs.pcap.inspector.entityCap.replace('{n}', String(entities.length))}
        </p>
      ) : null}
    </div>
  )
}

/** Never show full original in entity list when it's clearly an address — soft-mask middle. */
function maskEntity(value: string): string {
  if (value.includes('.') && /^\d/.test(value)) {
    const parts = value.split('.')
    if (parts.length === 4) return `${parts[0]}.${parts[1]}.*.*`
  }
  if (value.includes(':') && value.length >= 11) {
    return `${value.slice(0, 8)}…`
  }
  if (value.length > 24) return `${value.slice(0, 20)}…`
  return value
}

function CoverageTab() {
  const session = getPcapSession()!
  const vm = getPcapCoverageViewModel()!
  const setFilter = usePcapStore((s) => s.setFilter)

  const filterProtocol = (protocol: string) => {
    setFilter({ protocol })
    queueMicrotask(() => refreshPcapFilter())
  }

  return (
    <div className="pcap-coverage" data-plan-revision={vm.planRevision} data-testid="pcap-coverage-tab">
      <p className="pcap-coverage__legend" role="note" data-testid="pcap-coverage-legend">
        {cs.pcap.inspector.coverageLegend}
      </p>
      <table>
        <thead>
          <tr>
            <th>{cs.pcap.inspector.protocol}</th>
            <th>{cs.pcap.coverageUx.recognizedCol}</th>
            <th>{cs.pcap.coverageUx.protectedCol}</th>
            <th>{cs.pcap.coverageUx.userMeaningCol}</th>
            <th>{cs.pcap.inspector.unsupported}</th>
          </tr>
        </thead>
        <tbody>
          {vm.protocols.map((c) => (
            <tr key={c.protocol}>
              <td>
                <button
                  type="button"
                  className="pcap-coverage__proto-btn"
                  data-testid={`pcap-coverage-filter-${c.protocol}`}
                  title={c.technicalSourceLabel}
                  onClick={() => filterProtocol(c.filterProtocol)}
                >
                  {protocolLabel(c.protocol)}
                </button>
              </td>
              <td>{cs.pcap.coverageUx.packetsIn.replace('{n}', String(c.recognizedPacketCount))}</td>
              <td>{cs.pcap.coverageUx.packetsIn.replace('{n}', String(c.protectedPacketCount))}</td>
              <td>
                <span
                  className={`pcap-coverage__verdict pcap-coverage__verdict--${c.dominantUiStatus}`}
                  title={c.technicalSourceLabel}
                >
                  <StatusGlyph kind={coverageVerdictKind(c)} className="pcap-coverage__verdict-icon" />
                  {c.userVerdictLabel}
                </span>
              </td>
              <td className={c.unsupportedCount > 0 ? 'pcap-coverage__count--warn' : undefined}>
                {c.unsupportedCount}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {session.entityOccurrenceIndex.overflow ? (
        <p className="pcap-coverage__overflow" role="alert">
          {cs.pcap.inspector.entityOccurrenceOverflow}
        </p>
      ) : null}
      {session.analysis?.unsupportedLinkTypes.size ? (
        <p>
          {cs.pcap.inspector.unsupportedLinks}:{' '}
          {Array.from(session.analysis.unsupportedLinkTypes).join(', ')}
        </p>
      ) : null}
    </div>
  )
}

function ProfileTab() {
  const activeLevel = usePcapStore((s) => s.activePcapLevel)
  const session = getPcapSession()!

  const impact = cs.pcap.inspector.profileImpact
    .replace('{trunc}', String(session.statuses.truncatedCount))
    .replace('{unsup}', String(session.statuses.unsupportedCount))

  return (
    <div className="pcap-profile-tab">
      <p>
        <strong>{levelLabel(activeLevel)}</strong>
      </p>
      <p className="pcap-profile-tab__impact">{impact}</p>
      <p className="pcap-profile-tab__meta">
        {formatPacketCount(getPacketCount())} · {formatBytes(session.fileSize)}
      </p>
    </div>
  )
}
