/**
 * Synchronous PCAP plan rebuild adapter — legacy alias (Stage 9 delegates to worker port).
 */

export {
  createWorkerPcapPlanRebuildPort as createSyncPcapPlanRebuildPort,
  getPcapPlanRebuildPort,
  setPcapPlanRebuildPort,
  resetPcapPlanRebuildPort,
} from './workerPcapPlanRebuildPort'
