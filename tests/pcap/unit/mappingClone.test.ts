import { describe, expect, it } from 'vitest'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping.ts'

describe('SessionMapping clone/adopt', () => {
  it('clone preserves mappings independently from source', () => {
    const source = new SessionMapping()
    const alias = source.map('ipv4', '192.168.1.1')
    const copy = source.clone()
    expect(copy.get('ipv4', '192.168.1.1')).toBe(alias)
    copy.map('ipv4', '10.0.0.99')
    expect(source.get('ipv4', '10.0.0.99')).toBeUndefined()
  })

  it('adoptFrom transfers committed staging state', () => {
    const main = new SessionMapping()
    const staging = main.clone()
    staging.map('mac', 'aa:bb:cc:dd:ee:01')
    main.adoptFrom(staging)
    expect(main.get('mac', 'aa:bb:cc:dd:ee:01')).toBeDefined()
  })
})
