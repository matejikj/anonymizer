/**
 * Cancellation and generation ID support for PCAP processing.
 * Used to abort stale worker operations and ignore outdated responses.
 */

export class CancellationError extends Error {
  readonly generationId: string;
  constructor(generationId: string) {
    super('Operation cancelled');
    this.name = 'CancellationError';
    this.generationId = generationId;
  }
}

export class CancellationToken {
  private _cancelled = false;
  readonly generationId: string;

  constructor(generationId?: string) {
    this.generationId = generationId ?? crypto.randomUUID();
  }

  get cancelled(): boolean {
    return this._cancelled;
  }

  cancel(): void {
    this._cancelled = true;
  }

  throwIfCancelled(): void {
    if (this._cancelled) throw new CancellationError(this.generationId);
  }
}
