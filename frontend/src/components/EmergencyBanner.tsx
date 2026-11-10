import { useLanguage } from '../context/useLanguage'

export default function EmergencyBanner() {
  const { t } = useLanguage()

  return (
    <aside className="bg-helpline-navy text-surface-card py-space-sm px-space-md border-b border-helpline-navy shadow-sm z-50">
      <div className="max-w-[1200px] mx-auto flex flex-col md:flex-row items-center justify-between gap-space-sm text-center md:text-left">
        <div className="flex items-center gap-space-sm flex-wrap justify-center md:justify-start">
          <span className="inline-flex items-center justify-center p-1 bg-safety-amber text-on-surface rounded-full animate-pulse">
            <span className="material-symbols-outlined text-[18px] material-symbols-fill">crisis_alert</span>
          </span>
          <p className="font-label-md text-label-md tracking-tight">
            <strong className="text-safety-amber font-extrabold uppercase">
              {t.helplineBanner.split(':')[0]}:
            </strong>{' '}
            Call <span className="font-extrabold underline decoration-safety-amber decoration-2">1930</span> or visit{' '}
            <a
              className="underline hover:text-safety-amber font-semibold transition-colors"
              href="https://cybercrime.gov.in"
              rel="noopener noreferrer"
              target="_blank"
            >
              cybercrime.gov.in
            </a>
            <span className="hidden lg:inline text-outline-variant mx-1">|</span>
            <span className="text-surface-card/90 hidden sm:inline">{t.goldenHour}</span>
          </p>
        </div>
        <div className="flex items-center gap-space-md shrink-0">
          <a
            className="inline-flex items-center gap-1.5 bg-safety-amber hover:bg-amber-400 text-on-surface font-label-md text-label-md px-3 py-1.5 rounded-full font-bold shadow-sm transition-all active:scale-95"
            href="tel:1930"
          >
            <span className="material-symbols-outlined text-[16px] material-symbols-fill">call</span>
            {t.dial1930}
          </a>
        </div>
      </div>
    </aside>
  )
}
