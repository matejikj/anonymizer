#!/usr/bin/env node
/**
 * Release dependency audit for Krok 10.
 * Fails on high/critical vulnerabilities (ARCHITECTURE §12 / Krok 10 #3).
 */
import { execSync } from 'node:child_process'

try {
  execSync('npm audit --audit-level=high', {
    stdio: 'inherit',
    env: process.env,
  })
  console.log('check-audit: OK (no high/critical vulnerabilities)')
} catch {
  console.error('check-audit: FAILED — resolve npm audit findings before release')
  process.exit(1)
}
