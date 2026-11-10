/**
 * Bearer-token session store for the dashboard (multi-tenant auth mode,
 * audit M3).
 *
 * Threat model: the dashboard is a static SPA talking to the TrustLens API.
 * The access token lives in an in-memory variable and is mirrored to
 * sessionStorage so a page reload in the SAME TAB keeps the session; it is
 * deliberately NOT written to localStorage, so nothing survives the tab
 * closing. XSS on the dashboard would expose the token either way — the
 * short tab-scoped lifetime is the accepted trade-off, documented in the
 * README (authentication section). The backend issues 8-hour tokens
 * (TRUSTLENS_ACCESS_TOKEN_EXPIRY_MINUTES, default 480).
 *
 * The storage access is guarded so this module also works in non-browser
 * test environments (node) where sessionStorage does not exist — the token
 * then stays memory-only.
 */
const TOKEN_KEY = 'trustlens.access_token'

let token: string | null = null
let unauthorizedHandler: (() => void) | null = null

function sessionStore(): Storage | null {
  try {
    return typeof sessionStorage === 'undefined' ? null : sessionStorage
  } catch {
    // Storage access can throw (e.g. disabled cookies) — degrade to memory-only.
    return null
  }
}

/** Hydrate the in-memory token from sessionStorage at module load. */
token = sessionStore()?.getItem(TOKEN_KEY) ?? null

export function getAuthToken(): string | null {
  return token
}

export function setAuthToken(value: string | null): void {
  const trimmed = value?.trim()
  token = trimmed ? trimmed : null
  const store = sessionStore()
  if (!store) return
  if (token) {
    store.setItem(TOKEN_KEY, token)
  } else {
    store.removeItem(TOKEN_KEY)
  }
}

/** Register (or unregister) the callback fired when a protected call is
 *  rejected with 401 while a token was attached (expired/invalidated
 *  session). The UI uses this to reset to the login state. */
export function onUnauthorized(handler: (() => void) | null): void {
  unauthorizedHandler = handler
}

/** Drop the current token (if any) and notify the UI. Called by the API
 *  client when a protected request answers 401 with a token attached; the
 *  handler fires only when there actually was a session to lose. */
export function notifyUnauthorized(): void {
  const hadToken = token !== null
  token = null
  sessionStore()?.removeItem(TOKEN_KEY)
  if (hadToken) unauthorizedHandler?.()
}
