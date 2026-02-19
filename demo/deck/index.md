---
layout: DECK
title: "DECK Demo — Presentation Template"
description: "Every figure type rendered as slides. Lorem ipsum."
scope: DEMO
accent: "#f5a623"
accent_rgb: "245,166,35"
brand: "CANONIC"
subtitle: "DECK TEMPLATE"
footerTagline: "CANONIC DESIGN | DECK Demo | 255"
sections:

  - id: slide-title
    eyebrow: DEMO
    title: "CANONIC DECK"
    description: "Every figure type. One DECK layout. Sections become slides."

  - id: slide-timeline
    eyebrow: TIMELINE
    title: "14 Years. One Founder."
    description: "The timeline figure renders chronological events with optional amounts."
    dashboard:
      - span: 2
        figure:
          type: timeline
          items:
            - year: "2012"
              event: "FOUNDED"
              detail: "First commit"
            - year: "2016"
              event: "NIH GRANT"
              detail: "Cancer research"
              amount: "$2M"
            - year: "2024"
              event: "LAUNCH"
              detail: "Production"
            - year: "2026"
              event: "PMWC"
              detail: "Competition"

  - id: slide-metrics
    eyebrow: METRICS
    title: "Dashboard Cards"
    description: "Metric cards with values, labels, and trend indicators."
    dashboard:
      - metric:
          value: "$38M+"
          label: FUNDED
          change: "16 grants"
          trend: up
      - metric:
          value: "90"
          label: CLAIMS
          change: "6 patents"
          trend: up
      - metric:
          value: "20K+"
          label: PATIENTS
          change: "governed"
          trend: up
      - metric:
          value: "255"
          label: MAGIC
          change: "full score"
          trend: up

  - id: slide-architecture
    eyebrow: ARCHITECTURE
    title: "Six Patents. One Architecture."
    description: "Architecture diagram with frontend, backend, and standard libraries."
    dashboard:
      - span: 2
        figure:
          type: architecture
          label: "90 CLAIMS"
          layers:
            - id: PROV-004
              title: "NL to GPU"
              desc: FRONTEND
              type: frontend
            - id: PROV-001
              title: "Governance"
              desc: BACKEND
              type: backend
            - id: PROV-002
              title: "Economics"
              desc: STDLIB
              type: stdlib
            - id: PROV-005
              title: "Credentials"
              desc: STDLIB
              type: stdlib

  - id: slide-funnel
    eyebrow: TRANSPILER
    title: "English In. CUDA Out."
    description: "Funnel diagram with left inputs, bridge, and right outputs."
    dashboard:
      - span: 2
        figure:
          type: funnel
          left_label: "20 INDUSTRIES"
          left_items:
            - Healthcare
            - Finance
            - Legal
            - "+17 more"
          bridge_label: C
          bridge_sub: BRIDGE
          right_label: "20 LANGUAGES"
          right_items:
            - "CUDA"
            - "Metal"
            - "Python"
            - "+17 more"
          result: "= 400 GOVERNED COMBINATIONS"

  - id: slide-table
    eyebrow: TABLE
    title: "Product Tiers"
    description: "Tables render structured data within slides."
    dashboard:
      - span: 2
        table:
          headers:
            - Product
            - Tier
            - Description
          rows:
            - ["MammoChat", "FREE", "Open-source. Patient-facing."]
            - ["OncoNex", "ENTERPRISE", "51 hospitals. Global."]
            - ["CANONIC", "FOUNDATION", "6 patents. 90 claims."]

  - id: slide-score
    eyebrow: SCORE
    title: "The Future of Work"
    description: "Score meter and tier cards."
    dashboard:
      - span: 2
        figure:
          type: score-meter
          score: 255
          label: MAGIC

  - id: slide-tiers
    eyebrow: PRICING
    title: "Choose Your Tier"
    description: "Tier cards with pricing, features, and badges."
    dashboard:
      - span: 2
        figure:
          type: tier-cards
          cards:
            - name: COMMUNITY
              price: Free
              color: "rgba(255,255,255,0.8)"
              features: ["Access", "Community", "Earn"]
            - name: BUSINESS
              price: "$100/yr"
              color: "#5b9cf6"
              badges: ["HIPAA", "GDPR"]
              features: ["Deploy", "TALK", "Workflows"]
            - name: ENTERPRISE
              price: Contract
              color: "#bf5af2"
              badges: ["FDA", "EU AI Act"]
              features: ["255", "Custom", "White-label"]

  - id: slide-bars
    eyebrow: BAR CHART
    title: "Development Velocity"
    description: "Bar chart comparing values."
    dashboard:
      - span: 2
        figure:
          type: bar-chart
          bars:
            - label: "Pre-Agent"
              value: "2.5/day"
            - label: "Agent"
              value: "5.6/day"
            - label: "CANONIC"
              value: "29.4/day"

  - id: slide-close
    eyebrow: END
    title: "CANONIC DESIGN"
    description: "One theme. Every surface. 255."
---
