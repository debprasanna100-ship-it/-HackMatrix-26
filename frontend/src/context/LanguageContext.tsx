import { useState, type ReactNode } from 'react'
import { DICTIONARY, type LanguageCode } from './languages'
import { LanguageContext } from './useLanguage'

export function LanguageProvider({ children }: { children: ReactNode }) {
  const [language, setLanguage] = useState<LanguageCode>('en')

  return (
    <LanguageContext.Provider value={{ language, setLanguage, t: DICTIONARY[language] }}>
      {children}
    </LanguageContext.Provider>
  )
}
