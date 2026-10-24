# Spec: UI review follow-ups

Status: needs-triage

## Problem Statement

A walk through the web app (as a Platform Operator and as an Organization Administrator, at 1440px and 390px, light and dark colour schemes) found copy that contradicts an ADR, a dark theme that never applies, failure states that hide the whole app, settings that only the user menu reaches, a certificate list and page that make an Administrator work harder than needed, wizards that disable Next without saying why, an Operator and invitation flow that is bare, and pages that do not fit a phone.

## Solution

One ticket per finding under `issues/`, ordered roughly by impact: bugs and wrong copy first (01–04), then navigation (05–08), the Managed Certificate list and page (09–14), wizards and forms (15–19), the Operator and invitation pages (20–21), and layout and mobile (22–25). Tickets that need a design or product decision are `needs-triage`; the rest are `ready-for-agent`.

## Out of Scope

Server behaviour, except where a ticket needs a field the API does not yet return (noted in the ticket). New features beyond what each finding asks for.
