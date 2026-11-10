import { createContext, useContext } from 'react'
import { DICTIONARY, type LanguageCode, type Translations } from './languages'

export interface LanguageContextType {
  language: LanguageCode
  setLanguage: (lang: LanguageCode) => void
  t: Translations
}

export const LanguageContext = createContext<LanguageContextType>({
  language: 'en',
  setLanguage: () => {},
  t: DICTIONARY.en,
})

export function useLanguage() {
  return useContext(LanguageContext)
}
