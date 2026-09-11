import { describe, it, expect, vi } from 'vitest'

// bifrostApi builds on the shared axios instance from api.ts; these tests only
// exercise the pure predicate, so a minimal stub is enough to let it import.
vi.mock('axios', () => {
  const instance = {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
    interceptors: {
      request: { use: vi.fn() },
      response: { use: vi.fn() },
    },
  }
  return { default: { create: () => instance } }
})

import { keyIsRoutable, type BifrostKey } from './bifrostApi'

const key = (over: Partial<BifrostKey> = {}): BifrostKey => ({
  id: 'k1',
  name: 'default-azure-foundry-key',
  models: ['*'],
  weight: 1,
  ...over,
})

describe('keyIsRoutable', () => {
  // Bifrost's key-list response carries no `enabled` field at all — it
  // serialises its other bools (use_for_batch_api) even when false, so an
  // absent `enabled` means "not reported", not "disabled". Reading it as
  // falsy rejected every key the gateway returned and stranded installs
  // behind the setup wizard with a provider that routed perfectly well.
  it('treats an absent enabled as enabled', () => {
    expect(keyIsRoutable(key({ status: 'success' }))).toBe(true)
  })

  it('still honours an explicit enabled: false', () => {
    expect(keyIsRoutable(key({ status: 'success', enabled: false }))).toBe(false)
  })

  it('accepts an explicitly enabled verified key', () => {
    expect(keyIsRoutable(key({ status: 'success', enabled: true }))).toBe(true)
  })

  it('rejects a key the gateway could not verify', () => {
    expect(keyIsRoutable(key({ status: 'list_models_failed' }))).toBe(false)
  })

  // "unknown" is accepted only for a credential a human actually set, so a
  // fresh install's env-placeholder seed keys don't read as configured.
  it('accepts an unverified key with an operator-set credential', () => {
    expect(keyIsRoutable(key({ status: 'unknown', value: 'sk-real-value' }))).toBe(true)
  })

  it('rejects an unverified key still pointing at an env placeholder', () => {
    const envSeed = key({
      status: 'unknown',
      value: { value: '', ref: 'env.FOUNDRY_API_KEY', from_env: true } as never,
    })
    expect(keyIsRoutable(envSeed)).toBe(false)
  })
})
