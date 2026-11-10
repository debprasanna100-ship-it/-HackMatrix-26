import { beforeEach, describe, expect, it, vi } from 'vitest'
import {
  getAuthToken,
  notifyUnauthorized,
  onUnauthorized,
  setAuthToken,
} from './auth'

/** Reset the module's module-level token between tests: setting null clears
 *  both the in-memory token and (a real browser's) sessionStorage. */
beforeEach(() => {
  setAuthToken(null)
})

describe('auth token store', () => {
  it('stores, returns, and clears the token', () => {
    expect(getAuthToken()).toBeNull()
    setAuthToken('  tl-token-123  ')
    expect(getAuthToken()).toBe('tl-token-123')
    setAuthToken(null)
    expect(getAuthToken()).toBeNull()
  })

  it('treats blank tokens as no token', () => {
    setAuthToken('   ')
    expect(getAuthToken()).toBeNull()
  })

  it('overwrites a previous token', () => {
    setAuthToken('first')
    setAuthToken('second')
    expect(getAuthToken()).toBe('second')
    setAuthToken(null)
  })

  it('notifyUnauthorized clears the token and fires the handler once per call', () => {
    const handler = vi.fn()
    onUnauthorized(handler)
    setAuthToken('expired-token')
    notifyUnauthorized()
    expect(getAuthToken()).toBeNull()
    expect(handler).toHaveBeenCalledTimes(1)
    // A second notification with no token must not re-fire the handler.
    notifyUnauthorized()
    expect(handler).toHaveBeenCalledTimes(1)
    onUnauthorized(null)
    setAuthToken('another')
    notifyUnauthorized()
    expect(handler).toHaveBeenCalledTimes(1)
  })

  it('notifyUnauthorized without a handler still clears the token', () => {
    onUnauthorized(null)
    setAuthToken('token')
    notifyUnauthorized()
    expect(getAuthToken()).toBeNull()
  })

  it('mirrors the token to sessionStorage when a browser storage exists', () => {
    // jsdom-free environment: sessionStorage is undefined here, so the store
    // degrades to memory-only. The guard is part of the contract.
    setAuthToken('browser-token')
    expect(getAuthToken()).toBe('browser-token')
    setAuthToken(null)
    expect(getAuthToken()).toBeNull()
  })
})
