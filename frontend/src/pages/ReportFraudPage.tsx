import { useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'

export default function ReportFraudPage() {
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()

  const [fullName, setFullName] = useState('')
  const [mobile, setMobile] = useState('')
  const [scamType, setScamType] = useState('Bank / KYC Updation Scam')
  const [lossAmount, setLossAmount] = useState('')
  const [targetBank, setTargetBank] = useState('State Bank of India')
  const [fraudsterUpi, setFraudsterUpi] = useState('')
  const [phishingUrl, setPhishingUrl] = useState(() => searchParams.get('url') || '')
  const [narrative, setNarrative] = useState('')
  const [evidenceFileName, setEvidenceFileName] = useState<string | null>(null)
  const [authorized, setAuthorized] = useState(false)
  const [submitting, setSubmitting] = useState(false)

  function handleFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    if (e.target.files && e.target.files[0]) {
      setEvidenceFileName(e.target.files[0].name)
    }
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!authorized) {
      alert('This demo cannot transmit anything to 1930 or cybercrime.gov.in. To file a REAL report, '
        + 'call 1930 or visit cybercrime.gov.in. Continuing here only creates a local demo record on this device.')
      return
    }

    setSubmitting(true)
    setTimeout(() => {
      // Demo-only record: clearly labelled as such. Nothing is transmitted to
      // 1930 / cybercrime.gov.in / any bank — the "acknowledgment" below is a
      // local placeholder, never an official NCRP number.
      const randomRef = `TL-DEMO-${Math.floor(10000 + Math.random() * 90000)}`
      const randomAck = 'DEMO — not an official NCRP number'

      const newRecord = {
        ref: randomRef,
        ncrpAck: randomAck,
        citizenName: fullName.trim() || 'Citizen User',
        mobile: `+91 ${mobile.trim()}`,
        scamType,
        amount: Number(lossAmount) || 25000,
        sourceBank: `${targetBank} (Protected)`,
        muleAccount: fraudsterUpi.trim() || 'mule.suspect.4921@upi (demo placeholder)',
        url: phishingUrl.trim() || 'http://sbi-instant-kyc-verification.top',
        status: 'In Progress',
        step: 3,
        elapsedMinutes: 5,
        reportedAt: 'Just Now',
      }

      localStorage.setItem(`incident_${randomRef}`, JSON.stringify(newRecord))
      setSubmitting(false)
      navigate(`/tracker/${randomRef}`)
    }, 1200)
  }

  return (
    <div className="w-full max-w-[1200px] mx-auto px-space-md md:px-margin py-space-xl flex flex-col gap-space-xl">
      {/* SECTION 5: DEDICATED VICTIM SUPPORT & AUTOMATED HELPLINE FORWARDING */}
      <section className="w-full bg-surface-card border border-border-subtle rounded-2xl shadow-sm p-space-md md:p-space-xl" id="victim-support">
        <div className="flex flex-col lg:flex-row gap-space-xl">
          {/* Left: Guidance & Steps */}
          <div className="lg:w-5/12 flex flex-col justify-between space-y-6">
            <div>
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-red-100 text-danger-red font-label-md text-label-md mb-3">
                <span className="material-symbols-outlined text-[16px]">emergency_home</span>
                <span>Dedicated Citizen Emergency Portal</span>
              </div>

              <h2 className="font-headline-lg text-headline-lg font-extrabold text-helpline-navy tracking-tight mb-2">
                Lost money or shared confidential details? Don't panic.
              </h2>

              <p className="text-on-surface-variant font-body-md text-body-md mb-space-lg leading-relaxed">
                TrustLens acts as a citizen bridge to the <strong>Citizen Financial Cyber Fraud Reporting System (1930)</strong>. Complete this form to generate an airtight forensic dossier and notify the official cyber cell.
              </p>

              {/* 3-Step Automated Process */}
              <div className="space-y-4">
                <div className="flex items-start gap-3">
                  <div className="w-8 h-8 rounded-full bg-primary-container text-white flex items-center justify-center font-bold text-sm shrink-0 shadow-sm">
                    1
                  </div>
                  <div>
                    <h4 className="font-title-md text-title-md font-bold text-on-surface">Enter Incident Timeline</h4>
                    <p className="font-body-sm text-body-sm text-on-surface-variant leading-relaxed">
                      Provide your registered mobile number and approximate transaction time for transaction hold priority.
                    </p>
                  </div>
                </div>

                <div className="flex items-start gap-3">
                  <div className="w-8 h-8 rounded-full bg-primary-container text-white flex items-center justify-center font-bold text-sm shrink-0 shadow-sm">
                    2
                  </div>
                  <div>
                    <h4 className="font-title-md text-title-md font-bold text-on-surface">Describe the Scam Pattern</h4>
                    <p className="font-body-sm text-body-sm text-on-surface-variant leading-relaxed">
                      Select whether you encountered fake electricity cut SMS, Telegram job task, or fake UPI QR scan.
                    </p>
                  </div>
                </div>

                <div className="flex items-start gap-3">
                  <div className="w-8 h-8 rounded-full bg-primary-container text-white flex items-center justify-center font-bold text-sm shrink-0 shadow-sm">
                    3
                  </div>
                  <div>
                    <h4 className="font-title-md text-title-md font-bold text-on-surface">Instant Forensic Dispatch</h4>
                    <p className="font-body-sm text-body-sm text-on-surface-variant leading-relaxed">
                      TrustLens gathers domain host data, IP headers, and forwards evidence to cybercrime.gov.in &amp; local state cyber units.
                    </p>
                  </div>
                </div>
              </div>
            </div>

            {/* Official Coordination Seal */}
            <div className="mt-space-lg p-space-md bg-surface-canvas rounded-xl border border-border-subtle">
              <div className="flex items-center gap-2 text-helpline-navy font-bold text-sm mb-1">
                <span className="material-symbols-outlined text-secondary text-[20px] material-symbols-fill">verified</span>
                <span>Official Coordination Seal</span>
              </div>
              <p className="text-xs text-on-surface-variant leading-relaxed">
                Demonstration interface inspired by MHA / CERT-In citizen guidance. This is <strong>NOT an
                official government service</strong> — nothing is transmitted to 1930, cybercrime.gov.in, or
                any bank, and entries never leave this device. To file a real report, call 1930 or visit
                cybercrime.gov.in.
              </p>
            </div>
          </div>

          {/* Right: Interactive Incident Filing Form */}
          <div className="lg:w-7/12 bg-surface-canvas border border-border-subtle rounded-xl p-space-md sm:p-space-lg">
            <form className="space-y-4" onSubmit={handleSubmit}>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                {/* Full Name */}
                <div>
                  <label className="block font-label-md text-label-md font-bold text-on-surface mb-1">
                    Citizen Full Name *
                  </label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. Rajesh Kumar Sharma"
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    className="w-full bg-surface-card border border-border-subtle rounded-lg px-3 py-2 text-sm text-on-surface focus:border-primary-container focus:ring-0 outline-hidden"
                  />
                </div>

                {/* Mobile Number */}
                <div>
                  <label className="block font-label-md text-label-md font-bold text-on-surface mb-1">
                    Mobile / WhatsApp Number *
                  </label>
                  <div className="flex">
                    <span className="inline-flex items-center px-3 text-xs font-bold text-on-surface-variant bg-surface-container border border-r-0 border-border-subtle rounded-l-lg">
                      +91
                    </span>
                    <input
                      type="tel"
                      required
                      placeholder="9876543210"
                      value={mobile}
                      onChange={(e) => setMobile(e.target.value)}
                      maxLength={10}
                      className="w-full bg-surface-card border border-border-subtle rounded-r-lg px-3 py-2 text-sm text-on-surface focus:border-primary-container focus:ring-0 outline-hidden"
                    />
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                {/* Scam Type */}
                <div>
                  <label className="block font-label-md text-label-md font-bold text-on-surface mb-1">
                    Scam Classification *
                  </label>
                  <select
                    value={scamType}
                    onChange={(e) => setScamType(e.target.value)}
                    className="w-full bg-surface-card border border-border-subtle rounded-lg px-3 py-2 text-sm text-on-surface focus:border-primary-container focus:ring-0 outline-hidden"
                  >
                    <option>Bank / KYC Updation Scam</option>
                    <option>Electricity Disconnection Threat SMS</option>
                    <option>Part-time Telegram / Youtube Like Job</option>
                    <option>Fake FedEx / Customs Courier Extortion</option>
                    <option>UPI QR Code Fraud / Reverse Charge</option>
                    <option>Digital Arrest / Police Impersonation</option>
                  </select>
                </div>

                {/* Financial Loss */}
                <div>
                  <label className="block font-label-md text-label-md font-bold text-on-surface mb-1">
                    Approximate Financial Loss (INR ₹)
                  </label>
                  <input
                    type="number"
                    placeholder="Enter ₹ amount (e.g. 25000)"
                    value={lossAmount}
                    onChange={(e) => setLossAmount(e.target.value)}
                    className="w-full bg-surface-card border border-border-subtle rounded-lg px-3 py-2 text-sm text-on-surface focus:border-primary-container focus:ring-0 outline-hidden"
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                {/* Source Bank */}
                <div>
                  <label className="block font-label-md text-label-md font-bold text-on-surface mb-1">
                    Targeted Source Bank
                  </label>
                  <input
                    type="text"
                    placeholder="e.g. State Bank of India, HDFC..."
                    value={targetBank}
                    onChange={(e) => setTargetBank(e.target.value)}
                    className="w-full bg-surface-card border border-border-subtle rounded-lg px-3 py-2 text-sm text-on-surface focus:border-primary-container focus:ring-0 outline-hidden"
                  />
                </div>

                {/* Fraudster UPI or Account */}
                <div>
                  <label className="block font-label-md text-label-md font-bold text-on-surface mb-1">
                    Fraudster UPI ID / Mule Account (If known)
                  </label>
                  <input
                    type="text"
                    placeholder="e.g. paytm-9892@paytm or A/C 99821..."
                    value={fraudsterUpi}
                    onChange={(e) => setFraudsterUpi(e.target.value)}
                    className="w-full bg-surface-card border border-border-subtle rounded-lg px-3 py-2 text-sm text-on-surface focus:border-primary-container focus:ring-0 outline-hidden"
                  />
                </div>
              </div>

              {/* Phishing URL / Sender Phone */}
              <div>
                <label className="block font-label-md text-label-md font-bold text-on-surface mb-1">
                  Suspicious Website Link or Sender Phone Number
                </label>
                <input
                  type="text"
                  placeholder="e.g. http://sbi-instant-kyc-verification.top or +91 98765 43210"
                  value={phishingUrl}
                  onChange={(e) => setPhishingUrl(e.target.value)}
                  className="w-full bg-surface-card border border-border-subtle rounded-lg px-3 py-2 text-sm font-mono text-on-surface focus:border-primary-container focus:ring-0 outline-hidden"
                />
              </div>

              {/* Detailed Narrative */}
              <div>
                <label className="block font-label-md text-label-md font-bold text-on-surface mb-1">
                  Detailed Incident Narrative
                </label>
                <textarea
                  rows={3}
                  placeholder="Describe what the fraudster promised or threatened, what link was clicked, phone numbers or UPI handles provided (e.g., paytm-9892@paytm)..."
                  value={narrative}
                  onChange={(e) => setNarrative(e.target.value)}
                  className="w-full bg-surface-card border border-border-subtle rounded-lg px-3 py-2 text-sm text-on-surface focus:border-primary-container focus:ring-0 outline-hidden"
                ></textarea>
              </div>

              {/* Evidence Upload Zone */}
              <div>
                <label className="block font-label-md text-label-md font-bold text-on-surface mb-1">
                  Attach Evidence (Screenshots of Chat, SMS, UPI Slip)
                </label>
                <label className="border-2 border-dashed border-border-subtle hover:border-primary-container bg-surface-card rounded-lg p-4 text-center cursor-pointer transition-colors block">
                  <input
                    type="file"
                    className="hidden"
                    accept="image/*,.pdf"
                    onChange={handleFileChange}
                  />
                  <span className="material-symbols-outlined text-outline text-[28px]">cloud_upload</span>
                  <p className="font-label-md text-label-md font-semibold text-on-surface mt-1">
                    {evidenceFileName ? `Selected: ${evidenceFileName}` : 'Click to upload image or drop files here'}
                  </p>
                  <p className="text-[11px] text-outline">Supports PNG, JPG, PDF up to 15MB</p>
                </label>
              </div>

              {/* Authorization Checkbox */}
              <div className="flex items-start gap-2.5 pt-1">
                <input
                  id="authCheckbox"
                  type="checkbox"
                  required
                  checked={authorized}
                  onChange={(e) => setAuthorized(e.target.checked)}
                  className="mt-1 h-4 w-4 rounded border-border-subtle text-primary-container focus:ring-0 cursor-pointer"
                />
                <label htmlFor="authCheckbox" className="text-xs text-on-surface-variant font-body-sm leading-tight cursor-pointer">
                  I authorize TrustLens to extract digital server forensics, compile an incident affidavit, and securely relay this dossier to the <strong>National Cyber Crime Reporting Portal (1930 / cybercrime.gov.in)</strong>.
                </label>
              </div>

              {/* Submit Button */}
              <button
                type="submit"
                disabled={submitting || !authorized}
                className="w-full inline-flex items-center justify-center gap-2 bg-helpline-navy hover:bg-primary-container text-white font-label-lg text-label-lg py-3.5 px-6 rounded-xl font-bold shadow-md transition-all active:scale-[0.99] disabled:opacity-50"
              >
                <span className="material-symbols-outlined text-[20px]">send_and_archive</span>
                {submitting
                  ? 'Compiling Forensic Dossier & Dispatching...'
                  : 'Submit & Dispatch to Indian Cyber Helpline (1930)'}
              </button>
            </form>
          </div>
        </div>
      </section>
    </div>
  )
}
