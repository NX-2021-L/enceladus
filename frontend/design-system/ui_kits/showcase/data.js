// Showcase — content + asset references.
window.showcaseData = {
  hero: {
    title: 'ENCELADUS',
    subtitle: 'The system that learns from itself.',
    byline: 'J Reese \u00b7 Solo Architect & Operator \u00b7 April 2026',
    badges: [
      { label: 'v3.0', variant: 'default' },
      { label: 'Active Production', variant: 'green' },
      { label: 'AWS Serverless', variant: 'default' },
      { label: 'Multi-Agent', variant: 'default' },
    ],
  },
  architecture: [
    { label: 'Infrastructure', body: '20 Lambda functions, 8 DynamoDB tables, 2 SQS FIFO queues, Neo4j AuraDB Free (graph-indexed search), CloudFront CDN, API Gateway HTTP v2, Cognito auth with Lambda@Edge' },
    { label: 'Frontend',       body: 'React 19 PWA with TypeScript, Vite, Tailwind CSS, TanStack React Query \u2014 mobile-first governance cockpit across all active projects with full primitive surface' },
    { label: 'Agent Interface', body: 'Code-mode MCP: 5 governed meta-tools (search, execute, get_compact_context, coordination, connection_health) over Streamable HTTP + OAuth 2.1/PKCE \u2014 89% schema reduction vs. raw mode' },
    { label: 'CI/CD',          body: '5 GitHub Actions workflows, nightly SHA-256 parity audits, secrets guardrail, 13 deployment types with semver changelog; component registry enforces deployment transition arcs at the infrastructure level' },
    { label: 'Multi-Agent',    body: 'Coordination API with dispatch heuristics and graph-indexed tracker search across Claude, OpenAI Codex, and AWS Bedrock; 10 typed relationship edges with weight, confidence, and provenance' },
  ],
  innovations: [
    {
      title: 'Governed Lesson Primitive',
      html: `The Lesson Primitive (<span class="record-id">ENC-FTR-052</span>) transforms operational history into institutional knowledge. Every lesson is a first-class governed record type, evidence-gated and append-only, constitutionally scored against four pillars (force/surrender, convergence/play, efficiency/love, intention/flow) and a vibe board before it can propose governance amendments. Cross-project knowledge mining scanned 2,789 records across 20 projects and produced 17 governed lessons \u2014 the first time Enceladus examined its own operational history as a knowledge asset.`,
    },
    {
      title: 'Exclusive Checkout Service',
      html: `Prevents agent collisions via atomic task ownership \u2014 only the owning session can advance status. Child tasks support parallel dispatch. Commit Approval IDs (CAI) gate code completion; Commit Complete IDs (CCI) are validated in PR bodies by GitHub Actions before merge. A checkout-service assistant subsystem auto-remediates misclassified tasks by relaxing deployment arcs when evidence confirms the mechanism, and can never tighten them.`,
    },
    {
      title: 'Evidence-Gated Lifecycle',
      html: `Task state machine (<code>open \u2192 in-progress \u2192 coding-complete \u2192 committed \u2192 pr \u2192 merged-main \u2192 deploy-success \u2192 closed</code>) requires proof at every gate: commit SHAs validated against GitHub API, PR merge timestamps within 60-second tolerance, deployment evidence from GitHub Actions Jobs API with 7 validated fields. The component registry enforces the most-restrictive deployment arc across all components a task touches \u2014 infrastructure-level governance agents cannot bypass.`,
    },
    {
      title: 'Governance as Architecture',
      html: `SHA-256 governance hash required on every write mutation. MCP-API boundary policy ensures no tool handler directly accesses DynamoDB business tables, preventing transport-specific behavior drift. Write-source attribution on all mutations enables the audit Lambda to detect anomalies and alert via SNS. A CI-gated governance data dictionary enforces authoritative field semantics at both runtime and deploy time.`,
    },
    {
      title: 'Token Economy Design',
      html: `Every design decision weighs token cost. The code-mode MCP interface delivers an 89% tool-schema reduction. Graph-indexed tracker search collapses 20\u201350 sequential record lookups into 1\u20132 Neo4j traversal queries. Context nodes wrap every tracker record in mathematically-scored metadata enabling greedy knapsack context packing within token budgets. Prompt caching, strategic model selection, and batch API routing compress operational AI cost by an estimated 60\u201380% overall.`,
    },
    {
      title: 'Event-Driven Pipelines',
      html: `DynamoDB Streams \u2192 EventBridge Pipes \u2192 SQS FIFO (natural debounce via 5-min visibility timeout) \u2192 Lambda feed publisher \u2192 S3/CloudFront invalidation. The same stream architecture drives the Neo4j graph sync with graceful degradation \u2014 DynamoDB mutations are never blocked by graph failures, and agents receive structured fallback hints when the index is unreachable.`,
    },
  ],
  stats: [
    { n: '2,789+', l: 'Governed Records' },
    { n: '20',     l: 'Production Projects' },
    { n: '5',      l: 'Code-Mode Tools' },
    { n: '17',     l: 'Governed Lessons' },
    { n: '~$35',   l: 'Monthly Cost' },
    { n: '20',     l: 'Lambda Functions' },
    { n: '8',      l: 'DynamoDB Tables' },
    { n: '1',      l: 'Operator' },
  ],
  carousel: [
    { src: '../../assets/showcase-dashboard.jpg',      caption: 'Dashboard \u2014 project overview and active task feed' },
    { src: '../../assets/showcase-task-tracker.jpg',   caption: 'Task Tracker \u2014 governed lifecycle with status arc' },
    { src: '../../assets/showcase-feature-detail.jpg', caption: 'Feature Detail \u2014 acceptance criteria and evidence handshake' },
  ],
};
