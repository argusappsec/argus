# STRIDE Threat Model — <system name>

> Fill this worksheet in as you work through the `threat-modeling` skill. Keep
> every finding anchored to a concrete component, data flow, or trust boundary
> you read in the code.

## 1. System overview

- **Purpose:** <what the system does, in one or two sentences>
- **Entry points:** <HTTP routes, CLIs, queue consumers, webhooks — where input enters>
- **Data stores:** <databases, caches, files, secrets>
- **External dependencies:** <third-party services, APIs, libraries that carry trust>

## 2. Trust boundaries

List each boundary where data crosses from a less-trusted to a more-trusted
zone, and what enforces it (or what should).

| # | Boundary (from → to) | Crossing point in code | Control in place |
|---|----------------------|------------------------|------------------|
| 1 |                      |                        |                  |

## 3. STRIDE analysis per element

For each component or boundary, walk the six categories. Record a concrete
scenario or write "n/a — <why>". Leave nothing blank.

### Element: <name>

| Category | Threat? | Concrete scenario | Existing mitigation |
|----------|---------|-------------------|---------------------|
| **S**poofing               | | | |
| **T**ampering              | | | |
| **R**epudiation            | | | |
| **I**nformation disclosure | | | |
| **D**enial of service      | | | |
| **E**levation of privilege | | | |

## 4. Prioritised threats

Order by impact × likelihood; unmitigated and high-impact first.

| Priority | Threat | Element | Impact | Likelihood | Recommended mitigation |
|----------|--------|---------|--------|------------|------------------------|
| 1        |        |         |        |            |                        |

## 5. Summary

- **Highest-risk threat:** <one line>
- **Most exposed boundary:** <one line>
- **Top recommendation:** <the single most valuable mitigation to add>
