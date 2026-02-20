export default function AboutPage() {
  return (
    <div className="max-w-2xl mx-auto py-10 space-y-4">
      <h1 className="text-3xl font-bold text-vault-accent">About</h1>
      <p className="text-white/80">
        Vault1337 is a malware analysis platform for uploading, storing, and statically
        analysing malware samples. Built with Django + Django REST Framework on the backend
        and React + Vite + Tailwind CSS on the frontend.
      </p>
      <ul className="list-disc list-inside text-white/70 space-y-1">
        <li>Static analysis: hex viewer, strings, LIEF, oletools, ExifTool, PDF tools</li>
        <li>IOC extraction and management</li>
        <li>YARA rule management and scanning</li>
        <li>IP intelligence: AbuseIPDB, Spur, VirusTotal, Shodan</li>
        <li>VirusTotal and MalwareBazaar sample retrieval</li>
      </ul>
    </div>
  )
}
