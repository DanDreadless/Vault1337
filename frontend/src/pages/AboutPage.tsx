import { APP_VERSION } from '../version'

// ── Reusable layout primitives ────────────────────────────────────────────────

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="space-y-3">
      <h2 className="text-xs font-semibold uppercase tracking-widest text-vault-accent/70 border-b border-white/10 pb-1">
        {title}
      </h2>
      {children}
    </section>
  )
}

function CapabilityCard({ title, items }: { title: string; items: string[] }) {
  return (
    <div className="bg-vault-dark border border-white/10 rounded-lg p-4 space-y-2">
      <p className="text-sm font-semibold text-white">{title}</p>
      <ul className="space-y-1">
        {items.map((item) => (
          <li key={item} className="flex items-start gap-2 text-xs text-white/60">
            <span className="text-vault-accent mt-0.5 shrink-0">›</span>
            {item}
          </li>
        ))}
      </ul>
    </div>
  )
}

function ThirdPartyRow({
  name,
  license,
  copyright,
  url,
}: {
  name: string
  license: string
  copyright: string
  url: string
}) {
  return (
    <tr className="border-t border-white/5">
      <td className="py-2 pr-4 text-sm text-white font-medium align-top">{name}</td>
      <td className="py-2 pr-4 text-xs text-white/50 font-mono align-top">{license}</td>
      <td className="py-2 pr-4 text-xs text-white/40 align-top">{copyright}</td>
      <td className="py-2 text-xs align-top">
        <a
          href={url}
          target="_blank"
          rel="noopener noreferrer"
          className="text-vault-accent/70 hover:text-vault-accent transition-colors"
        >
          Source ↗
        </a>
      </td>
    </tr>
  )
}

// ── Page ─────────────────────────────────────────────────────────────────────

export default function AboutPage() {
  return (
    <div className="max-w-4xl mx-auto py-10 space-y-10">

      {/* Hero */}
      <div className="flex flex-col md:flex-row md:items-end md:justify-between gap-4">
        <div className="space-y-2">
          <div className="flex items-center gap-3">
            <h1 className="text-4xl font-bold text-white tracking-tight">Vault<span className="text-vault-accent">1337</span></h1>
            <span className="text-xs font-mono bg-vault-accent/20 text-vault-accent border border-vault-accent/30 rounded px-2 py-0.5">
              v{APP_VERSION}
            </span>
          </div>
          <p className="text-base text-white/60 max-w-xl leading-relaxed">
            Enterprise malware analysis platform — static analysis, IOC management,
            threat intelligence, and YARA, in a single self-hosted solution built for
            SOC teams.
          </p>
        </div>
        <div className="flex gap-3 shrink-0">
          <a
            href="https://github.com/DanDreadless/Vault1337"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 px-4 py-2 rounded border border-white/20 text-sm text-white/70 hover:text-white hover:border-white/40 transition-colors"
          >
            <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24" aria-hidden="true">
              <path fillRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" clipRule="evenodd" />
            </svg>
            GitHub
          </a>
          <a
            href="https://www.vault1337.com"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 px-4 py-2 rounded bg-vault-accent text-sm text-white font-semibold hover:bg-vault-accent/80 transition-colors"
          >
            Documentation ↗
          </a>
        </div>
      </div>

      {/* Why Vault1337 */}
      <Section title="About">
        <div className="space-y-3 text-sm text-white/70 leading-relaxed">
          <p>
            Vault1337 was built to give malware analysts and SOC teams a single, self-hosted platform
            for static sample analysis — without relying on cloud sandboxes that may expose sensitive
            samples or require per-submission fees. The goal is a fast, structured workflow: ingest a
            sample, extract indicators, enrich them against external threat intel sources, and produce
            repeatable, auditable analysis — all inside your own infrastructure.
          </p>
          <p>
            Designed from the ground up for enterprise deployment, Vault1337 ships with role-based
            access control, full audit logging, JWT authentication, optional SSO integration, and a
            Management console for operational administration — everything a team needs to run it in a
            production SOC environment without custom wiring.
          </p>
        </div>
      </Section>

      {/* Capabilities */}
      <Section title="Capabilities">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          <CapabilityCard
            title="Static Analysis"
            items={[
              'PE / ELF / Mach-O parsing via LIEF & pefile',
              '.NET assembly analysis (dnfile)',
              'APK analysis (androguard)',
              'Disassembly via Capstone (x86/x64/ARM)',
              'Office documents & macros (oletools)',
              'PDF structure and content extraction',
              'Shellcode analysis & string extraction',
            ]}
          />
          <CapabilityCard
            title="Threat Intelligence"
            items={[
              'VirusTotal enrichment & sample retrieval',
              'MalwareBazaar sample retrieval',
              'AbuseIPDB IP reputation',
              'Shodan host intelligence',
              'Spur IP context',
              'OTX threat feeds',
              'MITRE ATT&CK technique mapping',
            ]}
          />
          <CapabilityCard
            title="IOC & YARA"
            items={[
              'Automated IOC extraction from samples',
              'IOC enrichment and verdict management',
              'YARA rule authoring and scanning',
              'STIX 2.1 export for IOCs and files',
              'IP and domain intelligence lookups',
              'Fuzzy similarity matching (simhash)',
            ]}
          />
          <CapabilityCard
            title="Platform"
            items={[
              'Role-based access control (Admin / Analyst / ReadOnly)',
              'Full audit logging — 30 event types',
              'SSO via Okta, Azure AD, Google, OIDC, GitHub',
              'JWT authentication with token blacklisting',
              'Management console for staff administration',
              'CyberChef integration (self-hosted)',
            ]}
          />
          <CapabilityCard
            title="Operations"
            items={[
              'PostgreSQL with on-demand pg_dump backup',
              'Docker / Kubernetes deployment',
              'Health endpoints for load-balancer probes',
              'Content-addressable sample storage by SHA256',
              'Gunicorn + WhiteNoise + NGINX production stack',
            ]}
          />
          <CapabilityCard
            title="API"
            items={[
              'Full REST API (Django REST Framework)',
              'OpenAPI schema + Swagger UI at /api/v1/docs/',
              'JWT bearer token authentication',
              'Per-endpoint RBAC permission enforcement',
              'Paginated, filterable endpoints throughout',
            ]}
          />
        </div>
      </Section>

      {/* Tech stack */}
      <Section title="Technology Stack">
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
          {[
            ['Backend', 'Django 5.x + DRF'],
            ['Frontend', 'React 19 + Vite + Tailwind CSS'],
            ['Database', 'PostgreSQL 16 / SQLite (dev)'],
            ['Auth', 'simplejwt + python-social-auth'],
            ['Analysis', 'LIEF, pefile, dnfile, oletools, capstone'],
            ['Threat Intel', 'STIX 2.1, MITRE ATT&CK'],
            ['Container', 'Docker (non-root, multi-stage build)'],
            ['Serving', 'Gunicorn + WhiteNoise + NGINX'],
          ].map(([label, value]) => (
            <div key={label} className="bg-vault-dark border border-white/10 rounded p-3 space-y-0.5">
              <p className="text-xs text-white/40 uppercase tracking-wide">{label}</p>
              <p className="text-xs text-white/80 font-medium">{value}</p>
            </div>
          ))}
        </div>
      </Section>

      {/* Licence */}
      <Section title="Licence">
        <div className="bg-vault-dark border border-white/10 rounded-lg p-5 space-y-3">
          <div className="flex items-center gap-3">
            <p className="text-sm font-semibold text-white">GNU Affero General Public License v3.0</p>
            <span className="text-xs font-mono bg-white/10 text-white/60 rounded px-2 py-0.5">AGPL-3.0</span>
          </div>
          <p className="text-sm text-white/60 leading-relaxed">
            Vault1337 is open-source software released under the GNU Affero General Public
            License v3.0. You are free to use, modify, and distribute this software, provided
            that any modifications and any software that incorporates or links to Vault1337 are
            also made available under the same licence. If you deploy Vault1337 as a network
            service, you must make the complete corresponding source code available to users of
            that service.
          </p>
          <div className="flex flex-wrap gap-3 pt-1">
            <a
              href="https://github.com/DanDreadless/Vault1337/blob/main/LICENSE"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1.5 text-sm text-vault-accent hover:text-vault-accent/80 font-medium transition-colors"
            >
              Read the full licence ↗
            </a>
            <span className="text-white/20">·</span>
            <a
              href="https://www.gnu.org/licenses/agpl-3.0.html"
              target="_blank"
              rel="noopener noreferrer"
              className="text-sm text-white/40 hover:text-white/60 transition-colors"
            >
              AGPL-3.0 on gnu.org ↗
            </a>
          </div>
          <div className="border-t border-white/10 pt-3 flex items-start gap-3">
            <div className="shrink-0 mt-0.5 w-1.5 h-1.5 rounded-full bg-vault-accent" />
            <p className="text-sm text-white/60">
              <span className="text-white font-medium">Enterprise licensing available.</span>{' '}
              Organisations requiring a commercial licence — including closed-source deployment
              rights and exemption from AGPL-3.0 copyleft obligations — can request terms via{' '}
              <a
                href="https://www.vault1337.com"
                target="_blank"
                rel="noopener noreferrer"
                className="text-vault-accent hover:underline"
              >
                vault1337.com
              </a>{' '}
              or the{' '}
              <a
                href="https://github.com/DanDreadless/Vault1337"
                target="_blank"
                rel="noopener noreferrer"
                className="text-vault-accent hover:underline"
              >
                GitHub repository
              </a>.
            </p>
          </div>
          <p className="text-xs text-white/30 pt-1">
            Copyright &copy; {new Date().getFullYear()} Vault1337.
          </p>
        </div>
      </Section>

      {/* Third-party acknowledgements */}
      <Section title="Third-Party Acknowledgements">
        <p className="text-xs text-white/50">
          Vault1337 incorporates the following open-source components. All copyright notices and
          licence terms are retained as required.
        </p>
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr className="text-xs text-white/30 uppercase tracking-wide">
                <th className="pb-2 pr-4 font-normal">Component</th>
                <th className="pb-2 pr-4 font-normal">Licence</th>
                <th className="pb-2 pr-4 font-normal">Copyright</th>
                <th className="pb-2 font-normal">Source</th>
              </tr>
            </thead>
            <tbody>
              <ThirdPartyRow
                name="CyberChef"
                license="Apache-2.0"
                copyright="Crown Copyright 2016 GCHQ"
                url="https://github.com/gchq/CyberChef"
              />
              <ThirdPartyRow
                name="Django"
                license="BSD-3-Clause"
                copyright="Django Software Foundation"
                url="https://www.djangoproject.com"
              />
              <ThirdPartyRow
                name="Django REST Framework"
                license="BSD-3-Clause"
                copyright="Encode OSS Ltd."
                url="https://www.django-rest-framework.org"
              />
              <ThirdPartyRow
                name="LIEF"
                license="Apache-2.0"
                copyright="Quarkslab"
                url="https://github.com/lief-project/LIEF"
              />
              <ThirdPartyRow
                name="oletools"
                license="BSD-3-Clause"
                copyright="Philippe Lagadec"
                url="https://github.com/decalage2/oletools"
              />
              <ThirdPartyRow
                name="Capstone"
                license="BSD-3-Clause"
                copyright="Nguyen Anh Quynh et al."
                url="https://www.capstone-engine.org"
              />
              <ThirdPartyRow
                name="dnfile"
                license="MIT"
                copyright="malwarefrank"
                url="https://github.com/malwarefrank/dnfile"
              />
              <ThirdPartyRow
                name="androguard"
                license="Apache-2.0"
                copyright="The Androguard Team"
                url="https://github.com/androguard/androguard"
              />
              <ThirdPartyRow
                name="STIX2 (python-stix2)"
                license="BSD-3-Clause"
                copyright="OASIS Open"
                url="https://github.com/oasis-open/cti-python-stix2"
              />
              <ThirdPartyRow
                name="PyExifTool"
                license="BSD (elected)"
                copyright="sylikc / Kevin M. Godby et al."
                url="https://github.com/sylikc/pyexiftool"
              />
              <ThirdPartyRow
                name="ExifTool"
                license="Artistic (Perl) — commercial use permitted"
                copyright="Phil Harvey"
                url="https://exiftool.org"
              />
              <ThirdPartyRow
                name="Python Social Auth"
                license="BSD-3-Clause"
                copyright="Matías Aguirre"
                url="https://github.com/python-social-auth/social-app-django"
              />
              <ThirdPartyRow
                name="React"
                license="MIT"
                copyright="Meta Platforms, Inc."
                url="https://react.dev"
              />
              <ThirdPartyRow
                name="Tailwind CSS"
                license="MIT"
                copyright="Tailwind Labs Inc."
                url="https://tailwindcss.com"
              />
            </tbody>
          </table>
        </div>
        <p className="text-xs text-white/30">
          Full licence texts for all dependencies are available in their respective source
          repositories. The CyberChef Apache-2.0 licence is bundled at{' '}
          <span className="font-mono">/cyberchef/LICENSE</span>.
        </p>
      </Section>

    </div>
  )
}
