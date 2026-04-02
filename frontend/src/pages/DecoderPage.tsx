/**
 * CyberChef integration — self-hosted via iframe.
 *
 * CyberChef is © Crown Copyright 2016 GCHQ, licensed under the Apache
 * License, Version 2.0.  The full licence text is distributed alongside the
 * CyberChef assets at /cyberchef/LICENSE and is reproduced in
 * docs/licensing.md.
 *
 * No modifications have been made to the CyberChef source code.
 * Source: https://github.com/gchq/CyberChef
 */
export default function DecoderPage() {
  return (
    // Fixed position below the navbar (h-14 = 3.5rem) to escape the layout's
    // padding and fill the full remaining viewport height.
    <div className="fixed left-0 right-0 bottom-0 z-50" style={{ top: '3.5rem' }}>
      <iframe
        src="/cyberchef/index.html"
        title="CyberChef — The Cyber Swiss Army Knife"
        className="w-full h-full border-0"
        sandbox="allow-scripts allow-same-origin allow-downloads allow-forms allow-modals"
      />
    </div>
  )
}
