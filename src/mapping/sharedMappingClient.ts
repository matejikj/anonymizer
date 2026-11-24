/**
 * Shared session mapping worker client for text and PCAP (Stage 18).
 */

import { MappingWorkerClient } from './mappingWorkerClient'

let sharedClient: MappingWorkerClient | null = null

export function getSharedMappingClient(): MappingWorkerClient {
  if (!sharedClient) {
    sharedClient = new MappingWorkerClient()
  }
  return sharedClient
}

export function setSharedMappingClientForTests(client: MappingWorkerClient | null): void {
  sharedClient?.terminate()
  sharedClient = client
}

export function resetSharedMappingClient(): void {
  sharedClient?.terminate()
  sharedClient = null
}
