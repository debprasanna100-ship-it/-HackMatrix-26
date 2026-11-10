import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { getAuthToken, setAuthToken } from './auth'
import { login, logout } from './client'

/** Minimal JSON Response helper for the mocked fetch. */
function jsonResponse(status: number, body: unknown): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
    headers: new Headers(),
  } as unknown as Response
}

beforeEach(() => {
  setAuthToken(null)
  vi.stubGlobal('fetch', vi.fn())
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('API client authentication (audit M3)', () => {
  it('login stores the bearer token and resolves to the identity', async () => {
    const mock = vi.fn()
      // POST /api/v1/auth/token
      .mockResolvedValueOnce(jsonResponse(200, { access_token: 'tok-1', token_type: 'bearer' }))
      // GET /api/v1/auth/me (token now attached)
      .mockResolvedValueOnce(jsonResponse(200, {
        authenticated: true, user_id: 'u1', email: 'a@example.com', role: 'user',
      }))
    vi.stubGlobal('fetch', mock)

    const me = await login('a@example.com', 'pw')
    expect(me.authenticated).toBe(true)
    expect(me.email).toBe('a@example.com')
    expect(getAuthToken()).toBe('tok-1')

    // The token endpoint call itself carried NO Authorization header (no
    // session yet) and the /me probe DID carry it.
    const tokenCall = mock.mock.calls[0] as [string, RequestInit]
    const tokenHeaders = (tokenCall[1]?.headers ?? {}) as Record<string, string>
    expect(tokenCall[0]).toBe('/api/v1/auth/token')
    expect(tokenHeaders['Authorization']).toBeUndefined()
    const meCall = mock.mock.calls[1] as [string, RequestInit]
    const meHeaders = (meCall[1]?.headers ?? {}) as Record<string, string>
    expect(meCall[0]).toBe('/api/v1/auth/me')
    expect(meHeaders['Authorization']).toBe('Bearer tok-1')
  })

  it('a failed login throws ApiError and stores no token', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(
      jsonResponse(401, { detail: { code: 'invalid_credentials', message: 'Email or password is incorrect.' } }),
    ))
    await expect(login('a@example.com', 'wrong')).rejects.toMatchObject({
      name: 'ApiError',
      status: 401,
      code: 'invalid_credentials',
    })
    expect(getAuthToken()).toBeNull()
  })

  it('a 401 on a protected call clears an expired token', async () => {
    setAuthToken('expired-token')
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(
      jsonResponse(401, { error: { code: 'invalid_credentials', message: 'Invalid or expired access token.' } }),
    ))
    const { analyzeUrl } = await import('./client')
    await expect(analyzeUrl('https://example.com/')).rejects.toMatchObject({ status: 401 })
    expect(getAuthToken()).toBeNull() // session dropped; AuthBar resets to login
  })

  it('protected calls attach the Bearer token when a session exists', async () => {
    setAuthToken('tok-2')
    const mock = vi.fn().mockResolvedValueOnce(
      jsonResponse(200, { report_id: 'r1', classification: 'low_risk' }),
    )
    vi.stubGlobal('fetch', mock)
    const { analyzeUrl } = await import('./client')
    await analyzeUrl('https://example.com/')
    const call = mock.mock.calls[0] as [string, RequestInit]
    const headers = (call[1]?.headers ?? {}) as Record<string, string>
    expect(headers['Authorization']).toBe('Bearer tok-2')
    setAuthToken(null)
  })

  it('logout clears the token without any network call', () => {
    setAuthToken('tok-3')
    const mock = vi.fn()
    vi.stubGlobal('fetch', mock)
    logout()
    expect(getAuthToken()).toBeNull()
    expect(mock).not.toHaveBeenCalled()
  })
})
