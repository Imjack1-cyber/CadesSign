import { useState, type ReactNode } from 'react'
import { IxMenuAboutItem, IxMessageBar, IxTabItem, IxTabs, IxTypography } from '@siemens/ix-react'
import { PageHeader } from './PageHeader'

interface Term { term: string; children: ReactNode }

const Terms = ({ items }: { items: Term[] }) => (
  <dl className="about-list">
    {items.map(({ term, children }) => (
      <div key={term}>
        <dt><IxTypography format="label" bold>{term}</IxTypography></dt>
        <dd><IxTypography format="body">{children}</IxTypography></dd>
      </div>
    ))}
  </dl>
)

const Section = ({ title, children }: { title: string; children: ReactNode }) => (
  <section className="stack-sm">
    <IxTypography format="h4">{title}</IxTypography>
    {children}
  </section>
)

const P = ({ children }: { children: ReactNode }) => <IxTypography format="body">{children}</IxTypography>

interface AboutSection { key: string; label: string; content: ReactNode }

/** The About sections, shown in the menu's About overlay or, in the top-nav layout, as a page. */
const ABOUT_SECTIONS: AboutSection[] = [
  {
    key: 'overview',
    label: 'Overview',
    content: (
      <div className="about-page">
        <Section title="CAdES B-LT Signer & Verifier">
          <P>
            A demo for creating and validating CAdES (CMS Advanced Electronic Signatures, ETSI EN 319 122-1)
            signatures. It uses the European Commission's DSS library (v6.4), a disposable test PKI and an
            in-process RFC 3161 timestamp authority, so it works entirely offline by default.
          </P>
        </Section>
        <Section title="How to use it">
          <Terms items={[
            { term: '1. Action', children: 'Choose Sign a document or Verify a signature.' },
            { term: '2. Files', children: 'Drop the file to sign, or the .p7s signature plus (for detached signatures) the original file.' },
            { term: '3. Options', children: 'Pick the signature level, packaging and digest, and optionally a TSA, OCSP/CRL endpoints or your own keystore.' },
            { term: '4. Review', children: 'Check the summary and pre-flight warnings, then run the operation.' },
            { term: '5. Result', children: 'Signing downloads <file>.p7s. Verification shows the outcome and, on request, the full ETSI validation report as XML.' },
          ]} />
        </Section>
        <Section title="Analytics">
          <P>
            Every sign and verify request is recorded with its settings (level, packaging, digest and which external
            sources were used). The Analytics view lets you filter, sort and export these records as CSV. File contents
            and passwords are not recorded.
          </P>
        </Section>
        <Section title="Architecture">
          <Terms items={[
            { term: 'Frontend', children: 'React + Siemens Industrial Experience (iX) design system.' },
            { term: 'Backend', children: 'Node.js / Express API (/api/sign, /api/verify, /api/stats) with an SQLite metrics database.' },
            { term: 'Engine', children: 'Java CLI (cades) built on DSS and BouncyCastle; also usable on its own: cades sign, cades verify, cades gen-pki, cades tsa.' },
          ]} />
        </Section>
      </div>
    ),
  },

  {
    key: 'levels',
    label: 'Signature levels',
    content: (
      <div className="about-page">
        <P>
          ETSI baseline profiles build on each other: each level contains everything from the level before it.
          The level requested is the target; the verifier reports the level the signature actually reaches.
        </P>
        <Terms items={[
          { term: 'B (B-B): Basic', children: 'CMS SignedData with the signing certificate reference, content type, message digest and algorithm protection. Proves integrity and identifies the signer, but not when the signature was made.' },
          { term: 'B-T: Timestamp', children: 'Adds an RFC 3161 signature timestamp from a Time Stamp Authority, proving the signature existed at a given time.' },
          { term: 'B-LT: Long-term', children: 'Embeds the full certificate chain and revocation data (OCSP responses / CRLs) inside the signature, so it can be validated years later without contacting external services, even after certificates expire. Revocation data must be dated after the signature timestamp.' },
          { term: 'B-LTA: Long-term with archive', children: 'Adds an archive timestamp over the signature and its validation material. Archive timestamps can be renewed before algorithms weaken, which makes LTA the choice for genuine long-term archival.' },
        ]} />
        <IxMessageBar type="info" persistent>
          Not to be confused with the older "CAdES-LT" form of ETSI TS 101 733, which is deprecated. This project implements the EN 319 122-1 baseline levels.
        </IxMessageBar>
      </div>
    ),
  },

  {
    key: 'packaging',
    label: 'Packaging & digest',
    content: (
      <div className="about-page">
        <Section title="Packaging">
          <Terms items={[
            { term: 'Detached (default)', children: 'The original file stays byte-identical and the signature is written beside it as a separate .p7s file. Keep both: verification needs the original and the signature.' },
            { term: 'Enveloping', children: 'The original content is embedded inside the .p7s file. Verification needs only the signature file.' },
          ]} />
          <P>
            CAdES signs opaque bytes, so any file type works (XML, PDF, images, text) without canonicalisation.
            If you need signatures inside an XML document or a container holding both, consider XAdES or ASiC-E instead.
          </P>
        </Section>
        <Section title="Hash digest">
          <Terms items={[
            { term: 'SHA-256 (default)', children: 'Widely supported and accepted by current validation policies.' },
            { term: 'SHA-384 / SHA-512', children: 'Longer digests for stricter policies or longer retention periods.' },
          ]} />
        </Section>
      </div>
    ),
  },

  {
    key: 'trust',
    label: 'Trust & revocation',
    content: (
      <div className="about-page">
        <Terms items={[
          { term: 'TSA URL', children: 'An external RFC 3161 Time Stamp Authority. Without it, the built-in in-process TSA is used.' },
          { term: 'OCSP / CRL URL', children: 'Online revocation sources instead of the built-in offline ones that mint OCSP responses and CRLs on demand.' },
          { term: 'Keystore (.p12 / .pfx)', children: 'A PKCS#12 file with your own signing identity and trust anchors. Without it, the demo PKI (test-pki.p12) is used.' },
          { term: 'Ignore keystore trust anchors', children: 'When verifying, do not trust certificates from the keystore; only the system trust store and certificates embedded in the signature are used.' },
        ]} />
        <IxMessageBar type="warning" persistent>
          LT with an external TSA: a public TSA chains to a CA that the offline revocation sources do not know.
          Without OCSP/CRL endpoints that cover both the signer and the TSA chain, the signature can only reach B-T.
        </IxMessageBar>
        <P>
          The verifier is deliberately given only the trust anchor: no network fetching and no external revocation
          sources. Any revocation data it uses must come from inside the signature, which turns "is this really LT?"
          into a test rather than a claim.
        </P>
      </div>
    ),
  },

  {
    key: 'validation',
    label: 'Validation results',
    content: (
      <div className="about-page">
        <Terms items={[
          { term: 'TOTAL_PASSED: valid', children: 'The signature is cryptographically intact, the certificate chain leads to a trusted anchor and revocation checks succeeded.' },
          { term: 'INDETERMINATE', children: 'The signature could not be confirmed either way. Typical causes: the root certificate is not trusted (provide the keystore that holds it) or required revocation data is missing.' },
          { term: 'TOTAL_FAILED: invalid', children: 'The signature is broken, for example because the signed content was modified or the signature value does not match.' },
        ]} />
        <P>
          The simple report lists the indication, the level reached and whether it is long-term. The full report is
          the complete ETSI validation report (XML) with every validation step, the certificate chain and the
          revocation data used. You can download it from the result page.
        </P>
        <P>
          Signatures are standard CMS and also verify with OpenSSL: <code>openssl cms -verify -binary -inform DER</code>.
          The -binary flag is required.
        </P>
      </div>
    ),
  },

  {
    key: 'limitations',
    label: 'Limitations & privacy',
    content: (
      <div className="about-page">
        <IxMessageBar type="alarm" persistent>
          Demo only: signatures created here are not legally valid. The trust anchor is a disposable test CA and
          timestamps only assert the local system clock.
        </IxMessageBar>
        <Section title="Known limitations">
          <Terms items={[
            { term: 'Keys', children: 'RSA 2048 with SHA-256 by default, which satisfies the DSS default cryptographic constraints.' },
            { term: 'PKI', children: 'One self-signed root issues both the signing and TSA certificates. Real hierarchies have intermediates that need their own revocation data.' },
            { term: 'LT warnings', children: 'At B-LT there is no archive timestamp, so DSS may report missing revocation data for the TSA certificate. This is inherent to LT; use B-LTA for archival.' },
          ]} />
        </Section>
        <Section title="Going to production">
          <P>
            Use a real signing key (PKCS#12 keystore or PKCS#11 token), a qualified TSA, online OCSP/CRL sources,
            and a real trust list such as the EU List of Trusted Lists (LOTL).
          </P>
        </Section>
        <Section title="Data handling">
          <P>
            Uploaded files are processed by the backend and stored in its uploads folder; they are not deleted
            automatically. Do not upload confidential documents or production keys to a shared instance.
            Keystore passwords are passed to the signing engine and are not stored in the analytics database.
          </P>
        </Section>
      </div>
    ),
  },
]

/** Tabs shown inside the IX "About" overlay of the application menu. */
export function AboutContent() {
  return (
    <>
      {ABOUT_SECTIONS.map(s => (
        <IxMenuAboutItem key={s.key} tabKey={s.key} label={s.label}>{s.content}</IxMenuAboutItem>
      ))}
    </>
  )
}

/** The same sections as a standalone tabbed page, for layouts without the application menu. */
export function AboutPage() {
  const [active, setActive] = useState(ABOUT_SECTIONS[0].key)
  const section = ABOUT_SECTIONS.find(s => s.key === active) ?? ABOUT_SECTIONS[0]
  return (
    <div className="page">
      <PageHeader title="About" subtitle="CAdES B-LT Signer & Verifier" />
      <IxTabs activeTabKey={active}>
        {ABOUT_SECTIONS.map(s => (
          <IxTabItem key={s.key} tabKey={s.key} onClick={() => setActive(s.key)}>{s.label}</IxTabItem>
        ))}
      </IxTabs>
      <div role="tabpanel" aria-label={section.label}>{section.content}</div>
    </div>
  )
}
