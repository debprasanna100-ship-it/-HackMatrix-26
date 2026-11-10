export type LanguageCode = 'en' | 'hi' | 'bn' | 'ta' | 'te' | 'mr'

export interface LanguageOption {
  code: LanguageCode
  name: string
  nativeName: string
}

export const LANGUAGES: LanguageOption[] = [
  { code: 'en', name: 'English', nativeName: 'English' },
  { code: 'hi', name: 'Hindi', nativeName: 'हिन्दी' },
  { code: 'bn', name: 'Bengali', nativeName: 'বাংলা' },
  { code: 'ta', name: 'Tamil', nativeName: 'தமிழ்' },
  { code: 'te', name: 'Telugu', nativeName: 'తెలుగు' },
  { code: 'mr', name: 'Marathi', nativeName: 'मराठी' },
]

export interface Translations {
  helplineBanner: string
  goldenHour: string
  dial1930: string
  scanUrl: string
  incidentTracker: string
  threatRadar: string
  reportFraud: string
  verifyOnChain: string
  emergencyReport: string
  heroBadge: string
  heroTitle: string
  heroTitleHighlight: string
  heroDesc: string
  placeholderUrl: string
  analyzeBtn: string
  analyzingBtn: string
  sampleScans: string
  sampleKyc: string
  sampleElectricity: string
  sampleLegit: string
}

export const DICTIONARY: Record<LanguageCode, Translations> = {
  en: {
    helplineBanner: 'National Cyber Crime Helpline: Call 1930 or visit cybercrime.gov.in',
    goldenHour: 'If you have lost money to a digital scam, report within the Golden Hour (2 hours) to freeze fraud accounts.',
    dial1930: 'Dial 1930 Helpline',
    scanUrl: 'Scan & Check',
    incidentTracker: '1930 Incident Tracker',
    threatRadar: 'Threat Radar & Reports',
    reportFraud: 'Report Fraud',
    verifyOnChain: 'Verify On-Chain',
    emergencyReport: 'Emergency Scam Report',
    heroBadge: 'सुरक्षित इंटरनेट, सुरक्षित भारत • Indian Citizen Cyber Protection Shield',
    heroTitle: 'Is this website safe or a scam?',
    heroTitleHighlight: 'Check instantly before clicking or paying.',
    heroDesc: 'Verify suspicious bank alerts, electricity bill cutoff SMS links, part-time job portals, and fake APK download domains before entering OTP or UPI PINs.',
    placeholderUrl: 'Paste website link, SMS URL, or APK download link (e.g. sbi-kyc-update.online, free-recharge.in)...',
    analyzeBtn: 'Analyze Website',
    analyzingBtn: 'Scanning Target...',
    sampleScans: 'Try sample scans:',
    sampleKyc: 'Fake Banking KYC SMS link',
    sampleElectricity: 'Electricity Bill Threat SMS',
    sampleLegit: 'Legitimate Bank portal (onlinesbi.sbi)',
  },
  hi: {
    helplineBanner: 'राष्ट्रीय साइबर अपराध हेल्पलाइन: 1930 पर कॉल करें या cybercrime.gov.in पर जाएं',
    goldenHour: 'यदि आपने डिजिटल धोखाधड़ी में पैसे गंवाए हैं, तो खाते को फ्रीज कराने के लिए गोल्डन ऑवर (2 घंटे) के भीतर रिपोर्ट करें।',
    dial1930: '1930 हेल्पलाइन डायल करें',
    scanUrl: 'स्कैन और जांच',
    incidentTracker: '1930 शिकायत ट्रैकर',
    threatRadar: 'थ्रेट रडार और रिपोर्ट्स',
    reportFraud: 'धोखाधड़ी रिपोर्ट करें',
    verifyOnChain: 'ऑन-चेन सत्यापन',
    emergencyReport: 'आपातकालीन फ्रॉड रिपोर्ट',
    heroBadge: 'सुरक्षित इंटरनेट, सुरक्षित भारत • नागरिक साइबर सुरक्षा कवच',
    heroTitle: 'क्या यह वेबसाइट सुरक्षित है या धोखाधड़ी?',
    heroTitleHighlight: 'क्लिक या भुगतान करने से पहले तुरंत जांचें।',
    heroDesc: 'OTP या UPI पिन दर्ज करने से पहले संदिग्ध बैंक अलर्ट, बिजली बिल कटने के SMS लिंक, वर्क-फ्रॉम-होम जॉब पोर्टल और नकली APK लिंक सत्यापित करें।',
    placeholderUrl: 'वेबसाइट लिंक, SMS URL या APK डाउनलोड लिंक पेस्ट करें...',
    analyzeBtn: 'वेबसाइट का विश्लेषण करें',
    analyzingBtn: 'स्कैन जारी है...',
    sampleScans: 'नमूना स्कैन आज़माएं:',
    sampleKyc: 'फर्जी बैंक KYC SMS लिंक',
    sampleElectricity: 'बिजली बिल कटने की धमकी SMS',
    sampleLegit: 'असली बैंक पोर्टल (onlinesbi.sbi)',
  },
  bn: {
    helplineBanner: 'জাতীয় সাইবার ক্রাইম হেল্পলাইন: 1930 কল করুন বা cybercrime.gov.in ভিজিট করুন',
    goldenHour: 'সাইবার প্রতারণায় অর্থ হারালে প্রতারক অ্যাকাউন্ট ফ্রিজ করতে গোল্ডেন আওয়ার (২ ঘণ্টা)-এর মধ্যে রিপোর্ট করুন।',
    dial1930: '1930 হেল্পলাইনে কল করুন',
    scanUrl: 'স্ক্যান ও পরীক্ষা',
    incidentTracker: '1930 অভিযোগ ট্র্যাকার',
    threatRadar: 'হুমকি রাডার ও রিপোর্ট',
    reportFraud: 'প্রতারণার রিপোর্ট করুন',
    verifyOnChain: 'অন-চেইন যাচাইকরণ',
    emergencyReport: 'জরুরি প্রতারণা রিপোর্ট',
    heroBadge: 'সুরক্ষিত ইন্টারনেট, সুরক্ষিত ভারত • ভারতীয় নাগরিক সাইবার সুরক্ষা ঢাল',
    heroTitle: 'এই ওয়েবসাইটটি কি নিরাপদ নাকি প্রতারণা?',
    heroTitleHighlight: 'ক্লিক বা পেমেন্ট করার আগে তৎক্ষণাৎ যাচাই করুন।',
    heroDesc: 'OTP বা UPI পিন দেওয়ার আগে ভুয়ো ব্যাঙ্ক নোটিশ, বিদ্যুৎ বিল কাটার SMS, টেলিগ্রাম জব ও ভুয়ো APK লিংক যাচাই করুন।',
    placeholderUrl: 'ওয়েবসাইট লিংক, SMS URL বা APK ডাউনলোড লিংক পেস্ট করুন...',
    analyzeBtn: 'ওয়েবসাইট বিশ্লেষণ করুন',
    analyzingBtn: 'স্ক্যান করা হচ্ছে...',
    sampleScans: 'নমুনা স্ক্যান ট্রাই করুন:',
    sampleKyc: 'ভুয়ো ব্যাঙ্ক KYC SMS লিংক',
    sampleElectricity: 'বিদ্যুৎ বিল বিচ্ছিন্ন করার হুমকি SMS',
    sampleLegit: 'আসল ব্যাঙ্ক পোর্টাল (onlinesbi.sbi)',
  },
  ta: {
    helplineBanner: 'தேசிய சைபர் கிரைம் உதவி எண்: 1930 ஐ அழைக்கவும் அல்லது cybercrime.gov.in ஐப் பார்க்கவும்',
    goldenHour: 'பணத்தை இழந்திருந்தால், மோசடி கணக்குகளை முடக்க பொன்னான 2 மணி நேரத்திற்குள் புகாரளிக்கவும்.',
    dial1930: '1930 உதவி எண்ணை அழைக்கவும்',
    scanUrl: 'ஸ்கேன் செய்து சரிபார்க்கவும்',
    incidentTracker: '1930 புகார் கண்காணிப்பு',
    threatRadar: 'அச்சுறுத்தல் ரேடார்',
    reportFraud: 'மோசடியை புகாரளிக்கவும்',
    verifyOnChain: 'ஆன்-செயின் சரிபார்ப்பு',
    emergencyReport: 'அவசர மோசடி புகார்',
    heroBadge: 'பாதுகாப்பான இணையம், பாதுகாப்பான பாரதம் • குடிமக்கள் சைபர் பாதுகாப்பு கவசம்',
    heroTitle: 'இந்த இணையதளம் பாதுகாப்பானதா அல்லது மோசடியா?',
    heroTitleHighlight: 'பணம் செலுத்துவதற்கு முன் உடனே சரிபார்க்கவும்.',
    heroDesc: 'OTP அல்லது UPI PIN உள்ளிடுவதற்கு முன் சந்தேகத்திற்கிடமான வங்கி விழிப்பூட்டல்கள் மற்றும் போலி APK இணைப்புகளை சரிபார்க்கவும்.',
    placeholderUrl: 'வலைத்தள இணைப்பு, SMS URL அல்லது APK இணைப்பை ஒட்டவும்...',
    analyzeBtn: 'வலைத்தளத்தை ஆய்வு செய்',
    analyzingBtn: 'ஆய்வு செய்யப்படுகிறது...',
    sampleScans: 'மாதிரி ஸ்கேன்களை முயற்சிக்கவும்:',
    sampleKyc: 'போலி வங்கி KYC SMS இணைப்பு',
    sampleElectricity: 'மின்சார கட்டண துண்டிப்பு SMS',
    sampleLegit: 'அங்கீகரிக்கப்பட்ட வங்கி போர்டல் (onlinesbi.sbi)',
  },
  te: {
    helplineBanner: 'జాతీయ సైబర్ క్రైమ్ హెల్ప్‌లైన్: 1930కి కాల్ చేయండి లేదా cybercrime.gov.in ని సందర్శించండి',
    goldenHour: 'డిజిటల్ స్కామ్‌లో డబ్బు పోగొట్టుకుంటే, ఖాతాలను స్తంభింపజేయడానికి గోల్డెన్ అవర్ (2 గంటలు) లోపల నివేదించండి.',
    dial1930: '1930 హెల్ప్‌లైన్‌కు కాల్ చేయండి',
    scanUrl: 'స్కాన్ & ధృవీకరించండి',
    incidentTracker: '1930 ఫిర్యాదు ట్రాకర్',
    threatRadar: 'థ్రెట్ రాడార్ & నివేదికలు',
    reportFraud: 'మోసాన్ని నివేదించండి',
    verifyOnChain: 'ఆన్-చైన్ ధృవీకరణ',
    emergencyReport: 'అత్యవసర మోసం నివేదిక',
    heroBadge: 'సురక్షిత ఇంటర్నెట్, సురక్షిత భారత్ • పౌర సైబర్ రక్షణ కవచం',
    heroTitle: 'ఈ వెబ్‌సైట్ సురక్షితమైనదా లేక మోసమా?',
    heroTitleHighlight: 'చెల్లించే ముందు తక్షణమే తనిఖీ చేయండి.',
    heroDesc: 'OTP లేదా UPI పిన్‌లను నమోదు చేయడానికి ముందు అనుమానాస్పద బ్యాంక్ హెచ్చరికలు మరియు విద్యుత్ బిల్లు SMS లింక్‌లను ధృవీకరించండి.',
    placeholderUrl: 'వెబ్‌సైట్ లింక్, SMS URL లేదా APK లింక్‌ను ఇక్కడ అతికించండి...',
    analyzeBtn: 'వెబ్‌సైట్‌ను విశ్లేషించండి',
    analyzingBtn: 'స్కాన్ చేస్తోంది...',
    sampleScans: 'నమూనా స్కాన్‌లను ప్రయత్నించండి:',
    sampleKyc: 'నకిలీ బ్యాంక్ KYC SMS లింక్',
    sampleElectricity: 'విద్యుత్ బిల్లు కట్ హెచ్చరిక SMS',
    sampleLegit: 'అధికారిక బ్యాంక్ పోర్టల్ (onlinesbi.sbi)',
  },
  mr: {
    helplineBanner: 'राष्ट्रीय सायबर गुन्हे हेल्पलाइन: 1930 डायल करा किंवा cybercrime.gov.in ला भेट द्या',
    goldenHour: 'सायबर फसवणुकीत पैसे गमावले असल्यास, खाती गोठवण्यासाठी गोल्डन अवर (२ तास) मध्ये तक्रार करा.',
    dial1930: '1930 हेल्पलाइन डायल करा',
    scanUrl: 'स्कॅन आणि पडताळणी',
    incidentTracker: '1930 तक्रार ट्रॅकर',
    threatRadar: 'थ्रेट रडार आणि अहवाल',
    reportFraud: 'फसवणूक नोंदवा',
    verifyOnChain: 'ऑन-चेन पडताळणी',
    emergencyReport: 'तातडीची फसवणूक नोंदणी',
    heroBadge: 'सुरक्षित इंटरनेट, सुरक्षित भारत • नागरिक सायबर सुरक्षा ढाल',
    heroTitle: 'ही वेबसाइट सुरक्षित आहे की फसवणूक?',
    heroTitleHighlight: 'क्लिक किंवा पैसे भरण्यापूर्वी लगेच तपासा.',
    heroDesc: 'OTP किंवा UPI पिन टाकण्यापूर्वी बनावट बँक इशारे, वीज बिल कट करण्याचे मेसेज आणि बनावट APK लिंक्स तपासा.',
    placeholderUrl: 'वेबसाइट लिंक, SMS URL किंवा APK डाउनलोड लिंक पेस्ट करा...',
    analyzeBtn: 'वेबसाइटचे विश्लेषण करा',
    analyzingBtn: 'स्कॅन सुरू आहे...',
    sampleScans: 'नमुने तपासा:',
    sampleKyc: 'बनावट बँक KYC SMS लिंक',
    sampleElectricity: 'वीज पुरवठा खंडित करण्याची धमकी SMS',
    sampleLegit: 'अधिकृत बँक पोर्टल (onlinesbi.sbi)',
  },
}
