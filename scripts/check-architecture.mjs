#!/usr/bin/env node
/**
 * Architecture enforcement guards.
 * Runs in CI via `npm run check:architecture` — not a local-only checklist.
 */
import { execFileSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const srcRoot = path.join(root, 'src')

const PURE_ENGINE_DIRS = [
  'engine',
  'pcap/sanitize',
  'pcap/capture',
  'pcap/protocols',
  'pcap/kernel',
  'pcap/plan',
  'pcap/discovery',
  'pcap/coverage',
  'pcap/reassembly',
  'pcap/displayFilter',
  'pcap/dissection',
  'pcap/checksums',
  'pcap/domain',
  'mapping',
  'domain',
  'crypto',
]

const DOMAIN_DIRS = ['domain', 'pcap/domain']

const UI_FORBIDDEN_IMPORTS = [
  { name: 'react', re: /from\s+['"]react['"]/ },
  { name: 'react-dom', re: /from\s+['"]react-dom['"]/ },
  { name: 'zustand', re: /from\s+['"]zustand['"]/ },
  { name: 'components/', re: /from\s+['"][^'"]*\/components\// },
  { name: 'features/', re: /from\s+['"][^'"]*\/features\// },
]

const PRESET_INLINE_PATTERNS = [
  { name: 'payloadPolicy truncate-unsupported', re: /payloadPolicy:\s*['"]truncate-unsupported['"]/ },
  { name: 'removed metadataPolicy', re: /\bmetadataPolicy\s*:/ },
  { name: 'removed unsupportedPolicy', re: /\bunsupportedPolicy\s*:/ },
  { name: 'inline PresetDefinition', re: /\bPresetDefinition\s*=\s*\{/ },
  { name: 'duplicate SANITIZATION_PRESETS', re: /\bSANITIZATION_PRESETS\s*=/ },
  {
    name: 'inline preset profile object',
    re: /\{\s*[^}]{0,400}\bpreset\s*:\s*['"](?:safe|diagnostic|addresses-only)['"][^}]{0,400}\bprotocols\s*:\s*\{/,
  },
]

const WORKER_PROTOCOL_FILES = [
  'src/workers/protocol.ts',
  'src/pcap/processing/workerProtocol.ts',
  'src/pcap/export/workerProtocol.ts',
  'src/pcap/recovery/worker/protocol.ts',
  'src/mapping/protocol.ts',
]

const EXHAUSTIVE_UNION_CHECKS = [
  {
    file: 'src/pcap/coverage/statusLabels.ts',
    pattern: /Record<CoverageStatus,/,
    label: 'CoverageStatus exhaustive labels',
  },
  {
    file: 'src/pcap/discovery/intentKind.ts',
    pattern: /assertNever/,
    label: 'TransformationIntent exhaustiveness',
  },
  {
    file: 'src/pcap/profile/profileImpact.ts',
    pattern: /ProfileImpactKind/,
    label: 'ProfileImpact classifier',
  },
  {
    file: 'src/domain/sourceArtifact.ts',
    pattern: /SourceKind/,
    label: 'SourceKind tagged union',
  },
  {
    file: 'src/mapping/canonicalize.ts',
    pattern: /assertNever/,
    label: 'IdentityCategory canonicalizer exhaustiveness',
  },
  {
    file: 'src/mapping/reverseIndex.ts',
    pattern: /ReverseIndex/,
    label: 'ReverseIndex',
  },
  {
    file: 'src/mapping/sessionLifecycle.ts',
    pattern: /releaseMappingSession/,
    label: 'Mapping session lifecycle',
  },
  {
    file: 'src/mapping/bundle/mappingBundleJsonCodec.ts',
    pattern: /parseMappingBundleJsonBytes/,
    label: 'Mapping bundle JSON codec',
  },
  {
    file: 'src/mapping/resolve/ahoCorasick.ts',
    pattern: /AhoCorasick/,
    label: 'Aho-Corasick resolve scanner',
  },
  {
    file: 'src/mapping/resolve/aliasIndex.ts',
    pattern: /AliasLookupIndex/,
    label: 'Alias lookup index',
  },
  {
    file: 'src/domain/capabilityContract.ts',
    pattern: /RESOLVE_WORKSPACE_LIMITS/,
    label: 'Resolve workspace limits',
  },
  {
    file: 'src/correlation/correlationSession.ts',
    pattern: /processCorrelationSession/,
    label: 'CorrelationSession orchestration',
  },
  {
    file: 'src/correlation/adapterRegistry.ts',
    pattern: /registerSourceAdapter/,
    label: 'SourceAdapter registry',
  },
  {
    file: 'src/correlation/textSourceAdapter.ts',
    pattern: /createTextSourceAdapter/,
    label: 'TextSourceAdapter',
  },
  {
    file: 'src/correlation/pcapSourceAdapter.ts',
    pattern: /createPcapSourceAdapter/,
    label: 'PcapSourceAdapter',
  },
  {
    file: 'src/correlation/correlationTransaction.ts',
    pattern: /runSourceTransaction/,
    label: 'Correlation staging transaction',
  },
  {
    file: 'src/correlation/correlationManifest.ts',
    pattern: /isCorrelationManifestStale/,
    label: 'Correlation session manifest',
  },
  {
    file: 'src/correlation/textMaterialization.ts',
    pattern: /countMaterializedTextSources/,
    label: 'Bounded text materialization',
  },
  {
    file: 'src/mapping/resolveJournal.ts',
    pattern: /ResolveJournalBatch/,
    label: 'Mapping resolve journal',
  },
  {
    file: 'src/mapping/mappingAuthority.ts',
    pattern: /resolveStaging/,
    label: 'MappingAuthority staging commit',
  },
  {
    file: 'src/mapping/crossFormat/contractRegistry.ts',
    pattern: /CROSS_FORMAT_CATEGORY_CONTRACTS/,
    label: 'Cross-format category contract registry',
  },
  {
    file: 'src/mapping/crossFormat/canonicalizers.ts',
    pattern: /canonicalizeCrossFormatCategory/,
    label: 'Cross-format canonicalizers',
  },
  {
    file: 'src/mapping/crossFormat/representation.ts',
    pattern: /constraintsCompatible/,
    label: 'Cross-format representation strategies',
  },
  {
    file: 'src/mapping/crossFormat/identityKey.ts',
    pattern: /correlationRegistryKey/,
    label: 'Cross-format correlation registry keys',
  },
  {
    file: 'src/correlation/profileCompatibility/effectivePolicy.ts',
    pattern: /compileCorrelationPolicy/,
    label: 'Correlation effective policy compiler',
  },
  {
    file: 'src/correlation/profileCompatibility/compatibility.ts',
    pattern: /evaluateProfileCompatibility/,
    label: 'Profile compatibility evaluator',
  },
  {
    file: 'src/correlation/profileCompatibility/profileImpactCompiler.ts',
    pattern: /classifyProfileImpact/,
    label: 'Profile impact classifier from effective policy',
  },
  {
    file: 'src/correlation/profileCompatibility/globalRebuild.ts',
    pattern: /runGlobalCorrelationRebuild/,
    label: 'Global correlation rebuild',
  },
  {
    file: 'src/correlation/import/sourcePreflightPort.ts',
    pattern: /probeSourceKind/,
    label: 'Multi-source content-based preflight port',
  },
  {
    file: 'src/correlation/import/correlationImportController.ts',
    pattern: /handleUniversalFileDrop/,
    label: 'Multi-source import orchestration',
  },
  {
    file: 'src/features/correlation-staging/MultiSourceDropzone.tsx',
    pattern: /MultiSourceDropzone/,
    label: 'Universal multi-source dropzone',
  },
  {
    file: 'src/features/correlation-staging/CorrelationStagingView.tsx',
    pattern: /CorrelationStagingView/,
    label: 'Correlation staging screen',
  },
  {
    file: 'src/correlation/correlationProgressModel.ts',
    pattern: /initCorrelationProgress/,
    label: 'Correlation processing progress model',
  },
  {
    file: 'src/correlation/correlationReviewModel.ts',
    pattern: /buildCorrelationEntityRows/,
    label: 'Correlation review workspace model',
  },
  {
    file: 'src/features/correlation-workspace/CorrelationProgressView.tsx',
    pattern: /CorrelationProgressView/,
    label: 'Correlation progress view',
  },
  {
    file: 'src/features/correlation-workspace/CorrelationWorkspace.tsx',
    pattern: /CorrelationWorkspace/,
    label: 'Correlation review workspace',
  },
  {
    file: 'src/correlation/export/correlationShareManifest.ts',
    pattern: /assertShareableManifestHasNoLeaks/,
    label: 'AI-shareable correlation manifest',
  },
  {
    file: 'src/correlation/export/correlationExportController.ts',
    pattern: /runCorrelationExport/,
    label: 'Multi-source export orchestration',
  },
  {
    file: 'src/features/correlation-workspace/CorrelationExportDialog.tsx',
    pattern: /CorrelationExportDialog/,
    label: 'Correlation export dialog',
  },
  {
    file: 'src/features/correlation-workspace/CorrelationCompletionView.tsx',
    pattern: /CorrelationCompletionView/,
    label: 'Correlation completion view',
  },
  {
    file: 'src/features/resolve-only/MappingResolveWorkspace.tsx',
    pattern: /MappingResolveWorkspace/,
    label: 'Mapping resolve return workspace',
  },
  {
    file: 'src/features/resolve-only/resolveReturnController.ts',
    pattern: /openResolveReturnFromEmpty/,
    label: 'Resolve-only return flow controller',
  },
  {
    file: 'src/features/resolve-only/MaskedOriginal.tsx',
    pattern: /MaskedOriginal/,
    label: 'Masked original reveal/copy',
  },
  {
    file: 'src/correlation/correlationPhaseModel.ts',
    pattern: /CorrelationUiPhase/,
    label: 'Authoritative correlation phase union',
  },
  {
    file: 'src/correlation/correlationLiveAnnouncer.ts',
    pattern: /announceCorrelationSource/,
    label: 'Throttled source ARIA live announcer',
  },
  {
    file: 'src/features/correlation-workspace/rovingKeyNavigate.ts',
    pattern: /rovingKeyNavigate/,
    label: 'Roving keyboard navigation helper',
  },
  {
    file: 'src/correlation/correlationWorkspaceController.ts',
    pattern: /enterCorrelationFailedPhase/,
    label: 'Failed-phase recovery entry',
  },
  {
    file: 'src/features/correlation-workspace/CorrelationWorkspace.tsx',
    pattern: /correlation-add-source/,
    label: 'Add-source UI in correlation workspace',
  },
  {
    file: 'src/correlation/import/sourcePreflightPort.ts',
    pattern: /mime-unsupported/,
    label: 'E-mail file rejected as unsupported source',
  },
  {
    file: 'scripts/release-correlation.mjs',
    pattern: /Correlation release/,
    label: 'Correlation release orchestrator',
  },
  {
    file: 'scripts/release-pack-artifact.mjs',
    pattern: /FORBIDDEN/,
    label: 'Sanitized release artifact packer',
  },
  {
    file: 'playwright.correlation-release.config.ts',
    pattern: /correlation-/,
    label: 'Tri-browser correlation gate config',
  },
  {
    file: 'src/app/sessionLifecycleCoordinator.ts',
    pattern: /export function resetApplication/,
    label: 'SessionLifecycleCoordinator public entry',
  },
  {
    file: 'src/app/sessionLifecycleInventory.ts',
    pattern: /LIFECYCLE_RESOURCE_INVENTORY/,
    label: 'Session lifecycle resource inventory',
  },
  {
    file: 'src/app/sessionLifecycleDispose.ts',
    pattern: /disposeNonTextSessionResources/,
    label: 'Idempotent session resource dispose',
  },
  {
    file: 'src/pcap/coverage/pcapCoverageViewModel.ts',
    pattern: /buildPcapCoverageViewModel/,
    label: 'PcapCoverageViewModel',
  },
  {
    file: 'src/components/ui/HelpPanel.tsx',
    pattern: /useModalFocusTrap/,
    label: 'HelpPanel accessible focus trap',
  },
]

function walk(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules' || entry.name === 'dist') continue
      walk(full, out)
    } else if (/\.(ts|tsx)$/.test(entry.name)) {
      out.push(full)
    }
  }
  return out
}

function stripComments(source) {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:])\/\/.*$/gm, '$1')
}

function rel(file) {
  return path.relative(root, file)
}

function parseImports(source) {
  const imports = []
  const re = /(?:import|export)\s+(?:type\s+)?(?:[\w*{}\s,]+?\s+from\s+)?['"]([^'"]+)['"]/g
  let m
  while ((m = re.exec(source)) !== null) {
    imports.push(m[1])
  }
  return imports
}

function resolveImport(fromFile, spec) {
  if (!spec.startsWith('.') && !spec.startsWith('/')) return null
  let base = path.resolve(path.dirname(fromFile), spec.replace(/\.ts$/, ''))
  for (const ext of ['', '.ts', '.tsx', '/index.ts']) {
    const candidate = base + ext
    if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) return candidate
  }
  return null
}

function isUnderDir(file, dirRel) {
  const dir = path.join(srcRoot, dirRel)
  return file.startsWith(dir + path.sep) || file === dir
}

function isEngineFile(file) {
  return PURE_ENGINE_DIRS.some((d) => isUnderDir(file, d))
}

function isDomainFile(file) {
  return DOMAIN_DIRS.some((d) => isUnderDir(file, d))
}

function isUiFile(file) {
  const r = rel(file)
  return (
    r.startsWith('src/components/') ||
    r.startsWith('src/features/') ||
    r.startsWith('src/app/shell/') ||
    /\/ui\//.test(r)
  )
}

const violations = []
const allSrcFiles = walk(srcRoot)

// 1. React/Zustand in pure engine dirs
for (const file of allSrcFiles) {
  if (!isEngineFile(file)) continue
  const code = stripComments(fs.readFileSync(file, 'utf8'))
  for (const rule of UI_FORBIDDEN_IMPORTS) {
    if (rule.re.test(code)) {
      violations.push(`${rel(file)}: engine dir must not import ${rule.name}`)
    }
  }
}

// 2. Engine/domain must not import UI layers
for (const file of allSrcFiles) {
  if (!isEngineFile(file) && !isDomainFile(file)) continue
  const code = fs.readFileSync(file, 'utf8')
  for (const spec of parseImports(code)) {
    const resolved = resolveImport(file, spec)
    if (!resolved) continue
    if (isUiFile(resolved)) {
      violations.push(`${rel(file)}: ${isDomainFile(file) ? 'domain' : 'engine'} must not import UI ${rel(resolved)}`)
    }
  }
}

// 3. file.arrayBuffer() in PCAP load path (allow bounded file.slice().arrayBuffer())
const PCAP_LOAD_FILES = [
  'src/pcap/ui/pcapLoadController.ts',
  'src/pcap/ui/pcapResourceCoordinator.ts',
  'src/pcap/capture/incrementalCaptureReader.ts',
  'src/pcap/capture/pcapReader.ts',
  'src/pcap/capture/pcapngReader.ts',
  'src/pcap/processing/processingOrchestrator.ts',
  'src/pcap/processing/pcapProcessingWorkerClient.ts',
  'src/correlation/pcapSourceAdapter.ts',
]

for (const relPath of PCAP_LOAD_FILES) {
  const full = path.join(root, relPath)
  if (!fs.existsSync(full)) continue
  const code = stripComments(fs.readFileSync(full, 'utf8'))
  if (/\bfile\.arrayBuffer\s*\(\s*\)/.test(code)) {
    violations.push(`${relPath}: production PCAP load must not call file.arrayBuffer()`)
  }
}

// 4. Inline preset construction outside canonical presets module
const PRESET_INLINE_SKIP = new Set([
  path.join(srcRoot, 'pcap/profile/presets.ts'),
  path.join(srcRoot, 'pcap/profile/pcapAnonymizationLevel.ts'),
  path.join(srcRoot, 'pcap/profile/schema.ts'),
])
for (const file of allSrcFiles) {
  if (PRESET_INLINE_SKIP.has(file)) continue
  const code = stripComments(fs.readFileSync(file, 'utf8'))
  for (const rule of PRESET_INLINE_PATTERNS) {
    if (rule.re.test(code)) {
      violations.push(`${rel(file)}: inline preset object (${rule.name}) — use pcap/profile/presets.ts`)
      break
    }
  }
}

// 5. Worker wire protocol: no unknown[] and versioned requests
for (const relPath of WORKER_PROTOCOL_FILES) {
  const full = path.join(root, relPath)
  if (!fs.existsSync(full)) continue
  const code = fs.readFileSync(full, 'utf8')
  if (/\bunknown\[\]/.test(code)) {
    violations.push(`${relPath}: worker wire protocol must not use unknown[]`)
  }
  // Request union members that lack protocolVersion (except legacy text worker chunk messages)
  if (relPath.includes('workers/protocol.ts')) {
    if (!/DETECTION_PROTOCOL_VERSION/.test(code) || !/EXPORT_PROTOCOL_VERSION/.test(code)) {
      violations.push(`${relPath}: text worker protocol must declare DETECTION_PROTOCOL_VERSION and EXPORT_PROTOCOL_VERSION`)
    }
  }
  if (relPath.includes('pcap/export/workerProtocol.ts')) {
    const cancelMatch = code.match(/\|\s*\{\s*type:\s*'cancel'[\s\S]*?\}/)
    if (cancelMatch && !/protocolVersion/.test(cancelMatch[0])) {
      violations.push(`${relPath}: cancel request must include protocolVersion`)
    }
  }
}

// 6. Exhaustive union anchor files
for (const check of EXHAUSTIVE_UNION_CHECKS) {
  const full = path.join(root, check.file)
  if (!fs.existsSync(full)) {
    violations.push(`missing ${check.file} (${check.label})`)
    continue
  }
  const code = fs.readFileSync(full, 'utf8')
  if (!check.pattern.test(code)) {
    violations.push(`${check.file}: ${check.label} guard missing`)
  }
}

// 7. Markdown link integrity (repo docs under anonymizer)
function collectMarkdownFiles(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules' || entry.name === 'dist') continue
      // Nested git checkouts (e.g. a local working copy kept inside anonym/) are not our docs.
      if (fs.existsSync(path.join(full, '.git'))) continue
      collectMarkdownFiles(full, out)
    } else if (entry.name.endsWith('.md')) {
      out.push(full)
    }
  }
  return out
}

/**
 * Only documents git would actually ship (tracked, or untracked-but-not-ignored) are checked:
 * gitignored local material (scratch notes, a nested working copy, agent skills) may link
 * anywhere. Falls back to a plain directory walk outside a git checkout.
 */
function listShippedMarkdownFiles() {
  try {
    const out = execFileSync(
      'git',
      ['ls-files', '--cached', '--others', '--exclude-standard', '-z', '--', '*.md'],
      { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 64 * 1024 * 1024 },
    )
    const files = out
      .split('\0')
      .filter(Boolean)
      .map((f) => path.join(root, f))
      .filter((f) => fs.existsSync(f))
    // An empty list means git isn't telling us anything useful (never "nothing to check").
    return files.length > 0 ? files : null
  } catch {
    return null
  }
}

const MD_FILES = listShippedMarkdownFiles() ?? collectMarkdownFiles(root)

function checkMarkdownLinks(file) {
  const content = fs.readFileSync(file, 'utf8')
  const dir = path.dirname(file)
  const linkRe = /\[[^\]]*\]\(([^)]+)\)/g
  let m
  while ((m = linkRe.exec(content)) !== null) {
    const target = m[1].split('#')[0].trim()
    if (!target || target.startsWith('http://') || target.startsWith('https://') || target.startsWith('mailto:')) {
      continue
    }
    const resolved = path.resolve(dir, target)
    if (!fs.existsSync(resolved)) {
      violations.push(`${rel(file)}: broken link → ${target}`)
    }
  }
}

for (const md of MD_FILES) {
  checkMarkdownLinks(md)
}

// 8. assertNever module exists
if (!fs.existsSync(path.join(srcRoot, 'domain/assertNever.ts'))) {
  violations.push('missing src/domain/assertNever.ts')
}

// 9. Pseudonym generators must live under mapping/
const PSEUDONYM_ALLOW = new Set([
  path.join(srcRoot, 'mapping/textAliasEngine.ts'),
  path.join(srcRoot, 'engine/replacements.ts'),
  path.join(srcRoot, 'pcap/anonymization/mapping.ts'),
])
for (const file of allSrcFiles) {
  if (PSEUDONYM_ALLOW.has(file)) continue
  if (!isEngineFile(file)) continue
  const code = stripComments(fs.readFileSync(file, 'utf8'))
  if (/\bnextReplacement\s*\(/.test(code) || /\bgenerateTextAlias\s*\(/.test(code)) {
    violations.push(`${rel(file)}: pseudonym generation must go through MappingAuthority (mapping/)`)
  }
}

// 10. UI must not import mapping bundle codec internals
const BUNDLE_INTERNAL_RE = /mapping\/bundle\/(payloadCodec|mappingBundleJsonCodec)/
for (const file of allSrcFiles) {
  if (!isUiFile(file)) continue
  const code = fs.readFileSync(file, 'utf8')
  for (const spec of parseImports(code)) {
    if (BUNDLE_INTERNAL_RE.test(spec)) {
      violations.push(`${rel(file)}: UI must use bundle lifecycle client, not ${spec}`)
    }
    if (/\/crypto\//.test(spec) || /from\s+['"][^'"]*\/crypto['"]/.test(spec)) {
      violations.push(`${rel(file)}: UI must not import src/crypto internals (${spec})`)
    }
  }
}

// 12. correlation/ must not import React/Zustand
const CORRELATION_DIR = path.join(srcRoot, 'correlation')
for (const file of allSrcFiles) {
  if (!file.startsWith(CORRELATION_DIR + path.sep)) continue
  const code = stripComments(fs.readFileSync(file, 'utf8'))
  if (/from\s+['"]react['"]/.test(code) || /from\s+['"]zustand['"]/.test(code)) {
    violations.push(`${rel(file)}: correlation module must not import React/Zustand`)
  }
}

// 13. No feature-local design-system forks
const DS_FORK_DIRS = [path.join(srcRoot, 'features'), path.join(srcRoot, 'pcap', 'ui')]
const DS_FORK_PATTERNS = [
  { name: 'local Button component', re: /\bfunction\s+Button\s*\(/ },
  { name: 'local ExportSummary component', re: /\bfunction\s+ExportSummary\s*\(/ },
  { name: 'local CommandBar component', re: /\bfunction\s+CommandBar\s*\(/ },
]
for (const dir of DS_FORK_DIRS) {
  for (const file of allSrcFiles) {
    if (!file.startsWith(dir + path.sep)) continue
    if (!file.endsWith('.tsx')) continue
    const code = stripComments(fs.readFileSync(file, 'utf8'))
    for (const rule of DS_FORK_PATTERNS) {
      if (rule.re.test(code)) {
        violations.push(`${rel(file)}: ${rule.name} — import from src/design-system/ instead`)
      }
    }
  }
}

// 14. UI must not fan-out session/worker cleanup (SessionLifecycleCoordinator)
const LIFECYCLE_UI_DIRS = [
  path.join(srcRoot, 'features'),
  path.join(srcRoot, 'components'),
  path.join(srcRoot, 'pcap', 'ui'),
]
const LIFECYCLE_UI_FORBIDDEN = [
  { name: 'releaseMappingSession', re: /\breleaseMappingSession\s*\(/ },
  { name: 'teardownPcapSession', re: /\bteardownPcapSession\s*\(/ },
  { name: 'teardownPcapWorkers', re: /\bteardownPcapWorkers\s*\(/ },
  { name: 'disposeSessionController', re: /\bdisposeSessionController\s*\(/ },
  { name: 'releaseSingleEmailSession', re: /\breleaseSingleEmailSession\s*\(/ },
  { name: 'closeResolveReturnAndClear', re: /\bcloseResolveReturnAndClear\s*\(/ },
  { name: 'openResolveReturnFromEmpty', re: /\bopenResolveReturnFromEmpty\s*\(/ },
  { name: 'cancelPcapLoad', re: /\bcancelPcapLoad\s*\(/ },
  { name: 'closePcapWorkspace', re: /\bclosePcapWorkspace\s*\(/ },
  { name: 'cancelAnalysis', re: /\bcancelAnalysis\s*\(/ },
  { name: 'runFileAnalysis', re: /\brunFileAnalysis\s*\(/ },
  { name: 'runPasteAnalysis', re: /\brunPasteAnalysis\s*\(/ },
  { name: 'loadPcapFile', re: /\bloadPcapFile\s*\(/ },
]
const LIFECYCLE_UI_ALLOW = new Set([
  path.join(srcRoot, 'pcap', 'ui', 'pcapLoadController.ts'),
  path.join(srcRoot, 'pcap', 'ui', 'pcapSessionLifecycle.ts'),
  path.join(srcRoot, 'pcap', 'ui', 'pcapResourceCoordinator.ts'),
])
for (const file of allSrcFiles) {
  if (LIFECYCLE_UI_ALLOW.has(file)) continue
  if (!file.endsWith('.tsx')) continue
  const inUi = LIFECYCLE_UI_DIRS.some((dir) => file.startsWith(dir + path.sep))
  if (!inUi && path.basename(file) !== 'App.tsx') continue
  const code = stripComments(fs.readFileSync(file, 'utf8'))
  for (const rule of LIFECYCLE_UI_FORBIDDEN) {
    if (rule.re.test(code)) {
      violations.push(`${rel(file)}: UI must use SessionLifecycleCoordinator, not ${rule.name}()`)
    }
  }
}

// 15. Correlation PCAP must cross the processing-worker boundary and retain only
// payload-free discovery/container DTOs on the main thread.
const CORRELATION_PCAP_ADAPTER = path.join(srcRoot, 'correlation', 'pcapSourceAdapter.ts')
if (fs.existsSync(CORRELATION_PCAP_ADAPTER)) {
  const code = stripComments(fs.readFileSync(CORRELATION_PCAP_ADAPTER, 'utf8'))
  if (!/\bPcapProcessingWorkerClient\b/.test(code)) {
    violations.push('src/correlation/pcapSourceAdapter.ts: correlation PCAP must use PcapProcessingWorkerClient')
  }
  if (/pcap\/processing\/processingPipeline/.test(code)
    || /\bProcessingSession\b/.test(code)
    || /\bPacketEnvelope\b/.test(code)
    || /\.packets\b/.test(code)) {
    violations.push('src/correlation/pcapSourceAdapter.ts: correlation PCAP must not retain or process packet payload arrays on the main thread')
  }
}

// 16. File-backed text detection must consume the Blob incrementally. Building a complete
// canonical string before the worker starts is not a streaming detection path.
for (const relPath of [
  'src/features/import-log/streamImport.ts',
  'src/correlation/textDiscovery.ts',
]) {
  const full = path.join(root, relPath)
  if (!fs.existsSync(full)) continue
  const code = stripComments(fs.readFileSync(full, 'utf8'))
  const detectCall = code.search(/await\s+detectFileBytes\s*\(/)
  if (detectCall < 0) {
    violations.push(`${relPath}: file-backed text detection must use detectFileBytes()`)
  }
  const materialize = code.search(/lfParts\.join\s*\(/)
  if (materialize >= 0 && detectCall >= 0 && materialize < detectCall) {
    violations.push(`${relPath}: text must not be materialized before streaming worker detection`)
  }
}

const CORRELATION_TEXT_DISCOVERY = path.join(srcRoot, 'correlation', 'textDiscovery.ts')
if (fs.existsSync(CORRELATION_TEXT_DISCOVERY)) {
  const code = stripComments(fs.readFileSync(CORRELATION_TEXT_DISCOVERY, 'utf8'))
  if (!/input\.retainText\s*&&\s*lfFragment\.length/.test(code)) {
    violations.push('src/correlation/textDiscovery.ts: correlation discovery must not collect text unless retainText is enabled')
  }
}

const TEXT_CHUNKING = path.join(srcRoot, 'features', 'import-log', 'chunking.ts')
if (fs.existsSync(TEXT_CHUNKING)) {
  const code = stripComments(fs.readFileSync(TEXT_CHUNKING, 'utf8'))
  if (/\bfile\.arrayBuffer\s*\(\s*\)/.test(code)) {
    violations.push('src/features/import-log/chunking.ts: text fallback must use bounded Blob slices')
  }
}

// 17. PCAP recovery must not import text profile schema / PCAP profile persistence
//     and must not pull recovery writers into the anonymized-only export hot path.
const RECOVERY_DIR = path.join(srcRoot, 'pcap', 'recovery')
const RECOVERY_FORBIDDEN_IMPORT_RES = [
  { name: 'domain/configSchema', re: /domain\/configSchema/ },
  { name: 'domain/rulesetValidate', re: /domain\/rulesetValidate/ },
  { name: 'persistence/profileRepository', re: /persistence\/profileRepository/ },
  { name: 'persistence/pcapProfileRepository', re: /persistence\/pcapProfileRepository/ },
  { name: 'features/profiles', re: /features\/profiles/ },
  { name: 'pcap/profile/schema', re: /pcap\/profile\/schema/ },
]
if (fs.existsSync(RECOVERY_DIR)) {
  for (const file of allSrcFiles) {
    if (!file.startsWith(RECOVERY_DIR + path.sep)) continue
    const code = fs.readFileSync(file, 'utf8')
    const stripped = stripComments(code)
    for (const rule of RECOVERY_FORBIDDEN_IMPORT_RES) {
      for (const spec of parseImports(code)) {
        if (rule.re.test(spec)) {
          violations.push(`${rel(file)}: recovery must not import ${rule.name} (${spec})`)
        }
      }
    }
    if (/\bPcapProfile\b/.test(stripped)) {
      violations.push(`${rel(file)}: recovery modules must not reference PcapProfile`)
    }
    if (/\bprofileId\b/.test(stripped)) {
      violations.push(`${rel(file)}: recovery modules must not reference profileId`)
    }
  }
}

const EXPORT_HOT_PATH_NO_RECOVERY = [
  path.join(srcRoot, 'pcap', 'export', 'coordinator.ts'),
  path.join(srcRoot, 'pcap', 'export', 'incremental', 'incrementalExportEngine.ts'),
]
for (const file of EXPORT_HOT_PATH_NO_RECOVERY) {
  if (!fs.existsSync(file)) continue
  const code = fs.readFileSync(file, 'utf8')
  for (const spec of parseImports(code)) {
    if (/pcap\/recovery\/(export|restore)\//.test(spec)) {
      violations.push(`${rel(file)}: anonymized export hot path must not import recovery runtime ${spec}`)
    }
  }
}

// Worker may dynamically load recovery/export when recovery.enabled (step 3+).
// Static import of recovery/export|restore from the worker remains forbidden so the
// recovery-off module graph stays lean.
const EXPORT_WORKER = path.join(srcRoot, 'workers', 'pcap-export.worker.ts')
if (fs.existsSync(EXPORT_WORKER)) {
  const code = fs.readFileSync(EXPORT_WORKER, 'utf8')
  for (const spec of parseImports(code)) {
    if (/pcap\/recovery\/(export|restore)\//.test(spec)) {
      violations.push(`${rel(EXPORT_WORKER)}: use dynamic import for recovery runtime, not static ${spec}`)
    }
  }
}

// 18. T-01 kernel — single catalog, no parallel ALL_MODULES, no production packet retention
const ANALYSIS_TS = path.join(srcRoot, 'pcap', 'protocols', 'analysis.ts')
if (fs.existsSync(ANALYSIS_TS)) {
  const code = stripComments(fs.readFileSync(ANALYSIS_TS, 'utf8'))
  if (/\bALL_MODULES\b/.test(code)) {
    violations.push('src/pcap/protocols/analysis.ts: ALL_MODULES fork forbidden — use kernel/catalog.ts')
  }
  if (!/catalogLegacyModules/.test(code)) {
    violations.push('src/pcap/protocols/analysis.ts: must derive modules from catalogLegacyModules()')
  }
}

const PIPELINE_TS = path.join(srcRoot, 'pcap', 'processing', 'processingPipeline.ts')
if (fs.existsSync(PIPELINE_TS)) {
  const code = stripComments(fs.readFileSync(PIPELINE_TS, 'utf8'))
  if (!/sourceBlob/.test(code)) {
    violations.push('src/pcap/processing/processingPipeline.ts: ProcessingSession must retain sourceBlob')
  }
  if (!/retainPacketsForTests/.test(code)) {
    violations.push('src/pcap/processing/processingPipeline.ts: packet retention must be test-only gated')
  }
}

const WORKER_PROC = path.join(srcRoot, 'workers', 'pcap-processing.worker.ts')
if (fs.existsSync(WORKER_PROC)) {
  const code = stripComments(fs.readFileSync(WORKER_PROC, 'utf8'))
  if (/retainPacketsForTests\s*:\s*true/.test(code)) {
    violations.push('src/workers/pcap-processing.worker.ts: must not retain packets for tests in production worker')
  }
  if (/\.packets\b/.test(code)) {
    violations.push('src/workers/pcap-processing.worker.ts: must not reference session.packets')
  }
}

const ENGINE_TS = path.join(srcRoot, 'pcap', 'sanitize', 'engine.ts')
const APP_HANDLERS = path.join(srcRoot, 'pcap', 'kernel', 'applicationHandlers.ts')
if (fs.existsSync(ENGINE_TS) && fs.existsSync(APP_HANDLERS)) {
  const engine = fs.readFileSync(ENGINE_TS, 'utf8')
  if (!/APPLICATION_HANDLER_ORDER|applicationHandlers/.test(engine)) {
    violations.push('src/pcap/sanitize/engine.ts: must reference kernel applicationHandlers order')
  }
}

const CAPABILITY = path.join(srcRoot, 'domain', 'capabilityContract.ts')
if (fs.existsSync(CAPABILITY)) {
  const code = fs.readFileSync(CAPABILITY, 'utf8')
  if (!/PCAP_KERNEL_BUDGETS/.test(code)) {
    violations.push('src/domain/capabilityContract.ts: PCAP_KERNEL_BUDGETS missing')
  }
}

// T03 — Error / throw templates must not interpolate identity-bearing identifiers.
const SAFE_ERROR_SCAN_DIRS = [
  ...PURE_ENGINE_DIRS,
  'workers',
  'correlation',
  'pcap/anonymization',
  'pcap/ui',
  'pcap/export',
  'pcap/processing',
  'pcap/plan',
  'pcap/sanitize',
  'pcap/discovery',
]
// Forbid `${ident}` / `${ident + …}` but allow structural `${text.length}` / `${line}` as numbers
// only when followed by `.` (property) — bare `${text}` / `${canonical}` still fail.
const FORBIDDEN_ERROR_VALUE_RE =
  /(?:throw\s+new\s+\w*Error|new\s+\w*Error)\s*\(\s*(?:`[^`]*\$\{(?:canonical|rawCanonical|raw|value|originalSpelling|spelling|mappedIp|alias|ip|host|text|line)\b(?!\.)[^`]*`)/
for (const rel of SAFE_ERROR_SCAN_DIRS) {
  const dir = path.join(srcRoot, rel)
  if (!fs.existsSync(dir)) continue
  for (const file of walk(dir)) {
    const code = stripComments(fs.readFileSync(file, 'utf8'))
    if (FORBIDDEN_ERROR_VALUE_RE.test(code)) {
      violations.push(
        `${path.relative(root, file)}: Error message must not interpolate identity values (T03)`,
      )
    }
  }
}
if (!fs.existsSync(path.join(srcRoot, 'domain', 'safeWorkerError.ts'))) {
  violations.push('src/domain/safeWorkerError.ts: missing T03 worker error sanitizer')
}

// T63 — forbid collapsing coverageStatus / heuristic into a different status without proof.
const STATUS_COLLAPSE_SCAN_DIRS = ['pcap/sanitize', 'pcap/protocols', 'pcap/reassembly']
const FORBIDDEN_STATUS_COLLAPSE_RES = [
  {
    name: "coverageStatus === 'covered' ? 'covered' : 'redacted'",
    re: /coverageStatus\s*===\s*['"]covered['"]\s*\?\s*['"]covered['"]\s*:\s*['"]redacted['"]/,
  },
  {
    name: "heuristic → redacted/covered collapse",
    re: /===\s*['"]heuristic['"]\s*\?\s*['"](?:redacted|covered)['"]/,
  },
]
for (const rel of STATUS_COLLAPSE_SCAN_DIRS) {
  const dir = path.join(srcRoot, rel)
  if (!fs.existsSync(dir)) continue
  for (const file of walk(dir)) {
    const code = stripComments(fs.readFileSync(file, 'utf8'))
    for (const rule of FORBIDDEN_STATUS_COLLAPSE_RES) {
      if (rule.re.test(code)) {
        violations.push(
          `${path.relative(root, file)}: T63 forbids status collapse (${rule.name})`,
        )
      }
    }
  }
}
if (!fs.existsSync(path.join(srcRoot, 'pcap', 'sanitize', 'statusInvariant.ts'))) {
  violations.push('src/pcap/sanitize/statusInvariant.ts: missing T63 status invariant')
}

if (violations.length > 0) {
  console.error('Architecture guard failed:\n')
  for (const v of violations) console.error(`  - ${v}`)
  process.exit(1)
}

console.log(
  `check-architecture: OK (${allSrcFiles.length} TS files, ${MD_FILES.length} markdown files, ${WORKER_PROTOCOL_FILES.length} wire protocols)`,
)
