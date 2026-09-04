/** Abstract one-way network topology, not live telemetry or a geographic map. */
export function HeroTopology() {
  return <div className="hero-topology" aria-hidden="true">
    <svg viewBox="0 0 1440 900" fill="none" preserveAspectRatio="xMidYMid slice" focusable="false">
      <defs>
        <linearGradient id="hero-route-ink" x1="1080" y1="780" x2="1130" y2="170" gradientUnits="userSpaceOnUse">
          <stop stopColor="#ff5b12" /><stop offset="1" stopColor="#ff874b" />
        </linearGradient>
        <marker id="hero-route-arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="4" markerHeight="4" orient="auto-start-reverse">
          <path d="M1 1 9 5 1 9" fill="none" stroke="#ff874b" strokeWidth="1.5" />
        </marker>
      </defs>
      <g className="topology-links" transform="rotate(-32 1080 450)">
        <path d="M520 -100V290H760V540H960V1000M840 -100V150H1110V410H1440M1110 -100V-10H1290V710H1500M450 780H690V650H1160V900" strokeWidth="12" />
        <path d="M440 80H710V210H960V-80M540 170H630V410H830V780H1080V1030M630 340H1000V260H1190V90H1510M790 420H940V580H1210V790H1510M470 890H760V740H910M1030 940V720H1370V470H1510M1370 -90V340H1530M1060 450H1170V540H1350M720 -40V40H800M980 50H1030V170M1330 40H1410V230" strokeWidth="3" />
        <path d="M520 500H680V580M700 250H790V330M850 480H890V530M1010 320H1050V370M1130 30H1200M1160 590H1200M1340 830H1440V680M1380 370H1430V430M600 680V730H670" strokeWidth="2" />
        <g className="topology-junctions" strokeWidth="2">
          <rect x="619" y="329" width="22" height="22" rx="3" />
          <rect x="928" y="569" width="22" height="22" rx="3" />
          <rect x="1279" y="399" width="22" height="22" rx="3" />
          <rect x="1359" y="709" width="22" height="22" rx="3" />
        </g>
      </g>
      <path d="M1140 776 1033 591 1210 480 1064 229 1138 183" stroke="#ff5b12" strokeOpacity=".1" strokeWidth="19" />
      <path d="M1140 776 1033 591 1210 480 1064 229 1138 183" stroke="url(#hero-route-ink)" strokeWidth="5" markerEnd="url(#hero-route-arrow)" />
      <path d="m1138 183 52 86" stroke="#ff874b" strokeWidth="3" strokeDasharray="2 9" strokeLinecap="round" />
      <circle cx="1138" cy="183" r="40" fill="#ff5b12" fillOpacity=".06" />
      <circle cx="1138" cy="183" r="23" fill="#ff5b12" fillOpacity=".1" />
      <circle cx="1138" cy="183" r="6" fill="#ff5b12" stroke="#ffe7da" strokeWidth="1.5" />
      <circle cx="1190" cy="269" r="6" fill="#ff5b12" stroke="#ffe7da" strokeWidth="1.5" />
      <circle className="topology-pulse" cx="1140" cy="776" r="39" stroke="#ff5b12" strokeOpacity=".25" strokeWidth="2" />
      <circle cx="1140" cy="776" r="53" stroke="#ff5b12" strokeOpacity=".08" strokeWidth="2" />
      <circle cx="1140" cy="776" r="24" fill="#ff5b12" />
      <path d="m1130 788 3-25 18 17-11-1-10 9Z" fill="white" />
    </svg>
  </div>;
}
