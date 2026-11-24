/**
 * T41 — messaging buses and telemetry pipeline sanitizers.
 */

export {
  AMQP_TCP_PORT,
  isAmqpPortHint,
  looksLikeAmqp,
  sanitizeAmqp,
} from './amqp.ts'
export {
  KAFKA_TCP_PORT,
  isKafkaPortHint,
  looksLikeKafka,
  sanitizeKafka,
} from './kafka.ts'
export {
  NATS_TCP_PORT,
  isNatsPortHint,
  looksLikeNats,
  sanitizeNats,
} from './nats.ts'
export {
  STOMP_TCP_PORT,
  isStompPortHint,
  looksLikeStomp,
  sanitizeStomp,
} from './stomp.ts'
export {
  XMPP_CLIENT_PORT,
  XMPP_SERVER_PORT,
  isXmppPortHint,
  looksLikeXmpp,
  sanitizeXmpp,
} from './xmpp.ts'
export {
  GELF_PORT,
  isGelfPortHint,
  looksLikeGelf,
  sanitizeGelf,
} from './gelf.ts'
export {
  FLUENT_FORWARD_PORT,
  isFluentPortHint,
  looksLikeFluent,
  sanitizeFluentForward,
} from './fluent.ts'
export {
  OTLP_GRPC_PORT,
  OTLP_HTTP_PORT,
  isOtlpPortHint,
  looksLikeOtlp,
  sanitizeOtlp,
} from './otlp.ts'
