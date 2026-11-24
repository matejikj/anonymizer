/**
 * T29 — database wire-protocol sanitizers.
 */

export {
  POSTGRES_TCP_PORT,
  isPostgresPortHint,
  looksLikePostgres,
  sanitizePostgres,
} from './postgres.ts'
export {
  MYSQL_TCP_PORT,
  isMysqlPortHint,
  looksLikeMysql,
  sanitizeMysql,
} from './mysql.ts'
export {
  TDS_TCP_PORT,
  isTdsPortHint,
  looksLikeTds,
  sanitizeTds,
} from './tds.ts'
export {
  REDIS_TCP_PORT,
  isRedisPortHint,
  looksLikeRedis,
  sanitizeRedis,
} from './redis.ts'
export {
  MONGODB_TCP_PORT,
  isMongodbPortHint,
  looksLikeMongodb,
  sanitizeMongodb,
} from './mongodb.ts'
