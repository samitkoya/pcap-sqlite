# Design brief: local DNS evidence review

The product is a small, offline forensic workbench for a course presentation. The benchmark was the investigation workflow of eight security and network analysis products, using their own documentation. The study extracts patterns rather than branding or layouts to copy.

| Product / source | Relevant pattern | Adopt here / avoid here |
| --- | --- | --- |
| [Wireshark](https://www.wireshark.org/docs/wsug_html_chunked/ChUsePacketListPaneSection.html) | A selected packet in a dense list controls an adjacent detail pane; row navigation supports arrow keys. | Keep a chronological query trace and selected-query inspector. Avoid suggesting raw packet bytes are shown when only extracted fields are available. |
| [Elastic Security Network](https://www.elastic.co/guide/en/security/current/network-page-overview.html) | Network metrics, DNS event tables, and drill-down into a related timeline. | Preserve overview → domain → query progression. Avoid an unrelated map because the schema has no IP-location fields. |
| [Splunk Enterprise Security](https://docs.splunk.com/Documentation/ES/8.1.0/Admin/ManageAnalystWorkflows) | Findings are prioritized in a table with explicit score, status, and investigation context. | Rank by score and show rule contributions. Avoid implying this four-point score has Splunk's severity semantics. |
| [Security Onion](https://docs.securityonion.net/en/2.4/hunt.html) | A hunt view supports searching and pivoting from summary data into events. | Keep domain and query-name search visible near their data. Avoid adding a complex query language for ten course captures. |
| [Amazon GuardDuty](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_working-with-findings.html) | A finding table opens detail alongside evidence and can distinguish a finding from a final disposition. | Use “flagged for review” language and display source notes. Avoid labeling a capture malicious from the detector output. |
| [Datadog Security Signals](https://docs.datadoghq.com/security/application_security/threat_protection/security_signals/) | A signal list opens a details panel for triage. | Keep the selected query inspector compact and close to the trace. Avoid a separate route for a single query. |
| [Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/investigate-incidents) | Overview and entity detail views combine evidence, timeline, and drill-down. | Keep the approved two-tab structure, rule table, and timeline. Avoid adding case-management controls absent from the course scope. |
| [Zeek](https://docs.zeek.org/en/v7.1.1/about.html) | Structured network logs make raw observations inspectable and suitable for downstream analysis. | Treat SQLite query rows as evidence and domain scores as derived summaries. Avoid opaque scoring or claims of certainty. |

## Repeated patterns and product direction

Navigation is shallow: first a ranked overview, then a selected domain and its events. Tables carry precise values; charts provide context but do not replace the evidence. Status words and source notes establish trust more than decorative security imagery. Loading, empty, and error states should say what happened and how to recover. These are inferences from the benchmarked workflows, adapted to the much smaller schema here.

**Personality:** forensic, restrained, legible. **Density:** medium-high on desktop, progressively stacked on phones. **Tone:** specific, plain, and careful about uncertainty. The UI uses one cool blue accent for navigation and interaction, with amber/red/green reserved for semantic outcomes. The first viewport presents real capture counts, ranked domains, and an explicit “screening, not a verdict” note. It avoids gradients, glows, false statistics, and marketing copy.

## Implemented system

- Neutral dark surfaces and text are defined in `web/styles.css` as CSS variables; blue is the only non-semantic accent. Red/amber/green signal review status or operation feedback.
- Inter/system sans handles content and controls; Consolas/system monospace handles packet-like data. This is two font families at most, with system fallbacks.
- Spacing follows a 4/8 px base, with 6–8 px corners and one-pixel borders. Shadows are reserved for the mobile drawer. Motion is limited to its short reveal and respects reduced-motion settings.
- The reusable families are native buttons, labeled inputs/selects, accessible tabs, summary metrics, tables, rule results, query trace rows, and message states. A modal/toast/skeleton is not added because no workflow uses one; loading and errors are visible inline.
- Desktop keeps a narrow settings rail and wide data table. At 760 px the rail becomes a drawer; the query trace and inspector stack. The table scrolls within its own labeled region, while the page has no horizontal overflow at 360, 768, 1280, and 1920 px.

No competitor logos, assets, exact copy, or proprietary screen composition were reused.
