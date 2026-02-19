---
layout: default
title: "CANONIC DESIGN — Template Portfolio"
description: "Every section type, every figure, every component. Lorem ipsum demo."
scope: DEMO
accent: "#3b82f6"
accent_rgb: "59,130,246"
hero:
  badge: PORTFOLIO
  title: "CANONIC DESIGN"
  description: "Every section type. Every figure. Every component. One extensible layout."
  cta:
    - label: "View Source"
      href: "https://github.com/canonic-canonic/DESIGN"
      class: btn
    - label: "Back"
      href: "/"
      class: btn-secondary
stats:
  - value: "4"
    label: "Layouts"
  - value: "20+"
    label: "Section Types"
  - value: "15"
    label: "Figure Types"
  - value: "255"
    label: "Governed"
sections:

  # --- CARDS ---
  - id: cards-demo
    eyebrow: SECTION TYPE
    title: "Cards"
    description: "Responsive card grid. Auto-fit columns. Icons, titles, descriptions, links."
    cards:
      - icon: "\U0001F9E0"
        title: INTEL
        desc: "Knowledge extraction. Every insight sourced. Every claim evidenced."
        href: "#"
      - icon: "\U0001F4AC"
        title: CHAT
        desc: "Domain-specific conversation. Scoped, cited, traceable."
        href: "#"
      - icon: "\U0001F4B0"
        title: COIN
        desc: "Work-backed economics. Every coin backed by validated work."
        href: "#"
      - icon: "\U0001F916"
        title: AGENT
        desc: "Full autonomy. INTEL + CHAT + COIN composed."
        href: "#"

  # --- DASHBOARD (metrics) ---
  - id: dashboard-demo
    eyebrow: SECTION TYPE
    title: "Dashboard"
    description: "Metric cards with trend indicators. Span 1 or 2 columns."
    dashboard:
      - metric:
          value: "$38M+"
          label: FUNDED RESEARCH
          change: "16 grants, 3 clinical trials"
          trend: up
      - metric:
          value: "20K+"
          label: PATIENTS
          change: "On governed ledger"
          trend: up
      - metric:
          value: "90"
          label: PATENT CLAIMS
          change: "6 provisionals, single priority date"
          trend: up
      - metric:
          value: "255"
          label: MAGIC SCORE
          change: "Full compliance"
          trend: up

  # --- TABLE ---
  - id: table-demo
    eyebrow: SECTION TYPE
    title: "Table"
    description: "Structured data display. Headers and rows."
    table:
      headers:
        - Product
        - Tier
        - Description
      rows:
        - ["MammoChat", "FREE", "AI breast health companion. Open-source."]
        - ["OncoNex", "ENTERPRISE", "Precision oncology platform. 51 hospitals."]
        - ["CANONIC", "FOUNDATION", "Constitutional AI governance. 6 patents."]

  # --- TIERS ---
  - id: tiers-demo
    eyebrow: SECTION TYPE
    title: "Pricing Tiers"
    description: "Pricing cards with features, badges, and CTAs."
    tiers:
      - name: Community
        price: Free
        sub: Forever
        features:
          - Full platform access
          - Learning communities
          - Earn through work
        cta:
          label: Get Started
          href: "#"
      - name: Business
        price: "$100"
        sub: per year
        featured: true
        features:
          - Private workspace
          - Marketplace listing
          - Automated compliance
        cta:
          label: Subscribe
          href: "#"
          primary: true
      - name: Enterprise
        price: Contract
        sub: Tailored
        features:
          - Dedicated validation
          - Foundation-certified
          - Custom compliance
        cta:
          label: Contact
          href: "#"

  # --- FEATURE BLOCK ---
  - id: feature-demo
    eyebrow: SECTION TYPE
    title: "Feature Block"
    description: "Highlighted feature with tags and optional figure."
    feature:
      eyebrow: TRANSPILER
      title: "English In. CUDA Out."
      text: "The only system that translates natural language governance policy into GPU-compiled code while preserving governance constraints at every layer."
      tags:
        - CUDA
        - Metal
        - Python
        - Swift
        - Rust
        - WebKit

  # --- ABOUT ---
  - id: about-demo
    eyebrow: SECTION TYPE
    title: "About / Identity"
    description: "Full identity card: avatar, bio, publications, career lineage, organizations."
    about:
      name: "Dexter Hadley"
      title: "MD/PhD"
      location: "Orlando, FL"
      avatar: ""
      bio: "Chief of AI, UCF College of Medicine. Director of AI, ABOPM. Founder, CANONIC."
      tags:
        - Precision Medicine
        - Federated Learning
        - Governance
      publications:
        count: "121+"
        label: Publications
      lineage:
        - role: "Chief of AI"
          org: "UCF College of Medicine"
        - role: "Postdoc"
          org: "UCSF, Butte Lab"
        - role: "MD/PhD"
          org: "University of Pennsylvania"

  # --- BANNER ---
  - id: banner-demo
    eyebrow: SECTION TYPE
    title: "Banner"
    description: "Governance banner with badges and intersection mark."
    banner:
      eyebrow: GOVERNED
      title: "CANONIC Foundation"
      text: "The certification body for governed software."
      badges:
        - HIPAA
        - GDPR
        - SOX
        - FDA
        - EU AI Act

  # --- SWITCHER ---
  - id: switcher-demo
    eyebrow: SECTION TYPE
    title: "Switcher / Tabs"
    description: "Tabbed content panels. Click to switch."
    switcher:
      tabs:
        - id: tab-overview
          label: Overview
          default: true
          content: "<p>The Overview tab. This content switches when you click a different tab. Each tab can contain arbitrary HTML, cards, figures, or text.</p>"
        - id: tab-details
          label: Details
          content: "<p>The Details tab. Different content here. Useful for organizing complex pages into digestible chunks without page navigation.</p>"
        - id: tab-api
          label: API
          content: "<p>The API tab. Documentation, routes, endpoints. Anything structured.</p>"

  # --- PRODUCTS ---
  - id: products-demo
    eyebrow: SECTION TYPE
    title: "Products Grid"
    description: "App icon grid with badges."
    products:
      - icon: "\U0001F380"
        name: MammoChat
        desc: "Breast oncology companion"
        badge: LIVE
        href: "#"
      - icon: "\U0001F52C"
        name: OncoChat
        desc: "Pan-oncology intelligence"
        badge: LIVE
        href: "#"
      - icon: "\U0001FA7A"
        name: MedChat
        desc: "General medical assistant"
        badge: LIVE
        href: "#"

  # --- PROOF ---
  - id: proof-demo
    eyebrow: SECTION TYPE
    title: "Proof Block"
    description: "Monospace evidence block for formal claims."
    proof: |
      **Theorem 1.** Every CANONIC service validates to 255.

      *Proof.* By construction. The compiler enforces 8 governance dimensions,
      each scored 0-31. A service that compiles has passed all 8 validators.
      The sum is deterministic: 8 x 31 = 248 + 7 bonus = 255. QED.

  # --- CTA (section-level) ---
  - id: cta-section-demo
    eyebrow: SECTION TYPE
    title: "Section CTA"
    description: "Call-to-action buttons within a section."
    cta:
      buttons:
        - label: Primary Action
          href: "#"
        - label: Secondary Action
          href: "#"

cta:
  title: "Build With CANONIC DESIGN"
  description: "One theme. Every surface type. Pre-rendered by Jekyll."
  buttons:
    - label: "Use This Theme"
      href: "https://github.com/canonic-canonic/DESIGN"
    - label: "View DECK Demo"
      href: "/demo/deck/"
footer:
  links:
    - label: Foundation
      href: "https://canonic-canonic.github.io/FOUNDATION"
    - label: MAGIC
      href: "https://canonic-canonic.github.io/MAGIC"
    - label: GitHub
      href: "https://github.com/canonic-canonic/DESIGN"
  tagline: "CANONIC DESIGN | Template Portfolio | 255"
---
