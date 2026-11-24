/**
 * T31 — declarative proprietary / radio protocol descriptors.
 */

export type {
  WireProtocolDescriptor,
  DescriptorField,
  DescriptorMessageVariant,
  FieldDisposition,
} from './types.ts'
export { DESCRIPTOR_SCHEMA_VERSION } from './types.ts'
export { validateWireProtocolDescriptor } from './validate.ts'
export type { DescriptorValidationIssue, DescriptorValidationResult } from './validate.ts'
export {
  sanitizeFromDescriptor,
  descriptorPortHint,
} from './sanitizeFromDescriptor.ts'
export {
  listWireProtocolDescriptors,
  getWireProtocolDescriptor,
  assertAllDescriptorsValid,
} from './registry.ts'
export {
  rndDispatchLiteDescriptor,
  buildRndDispatchLiteDatagram,
  RND_DISPATCH_LITE_UDP_PORT,
  RND_DISPATCH_LITE_MAGIC,
} from './rndDispatchLite.ts'
export { DESCRIPTOR_TEMPLATE } from './template.ts'
