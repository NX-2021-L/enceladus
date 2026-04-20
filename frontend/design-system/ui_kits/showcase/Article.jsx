// Arch grid + Innovations + Stats + pull-quote.

function ArchGrid({ items }) {
  return (
    <div className="arch-grid">
      {items.map(it => (
        <div className="arch-card" key={it.label}>
          <div className="arch-label">{it.label}</div>
          <p>{it.body}</p>
        </div>
      ))}
    </div>
  );
}

function InnovationList({ items }) {
  return (
    <div>
      {items.map(it => (
        <div className="innovation-item" key={it.title}>
          <h3>{it.title}</h3>
          <p dangerouslySetInnerHTML={{ __html: it.html }} />
        </div>
      ))}
    </div>
  );
}

function StatsGrid({ stats }) {
  return (
    <div className="stats-grid">
      {stats.map(s => (
        <div className="stat-item" key={s.l}>
          <div className="stat-number">{s.n}</div>
          <div className="stat-label">{s.l}</div>
        </div>
      ))}
    </div>
  );
}

function BottomLineQuote() {
  return (
    <blockquote>
      <p>
        Enceladus is not a product for sale — it is an operational philosophy made manifest.
        It demonstrates that a single operator, armed with the right abstractions and governed AI
        agents, can build, maintain, and <em>learn from</em> production systems at a scale and
        quality level that would traditionally require a team. The platform's power comes not
        from complexity, but from the disciplined simplicity of treating every entity, every
        transition, every mutation, and now every lesson as an opportunity to enforce quality,
        accumulate wisdom, and align with values at the architectural level.
      </p>
    </blockquote>
  );
}

Object.assign(window, { ArchGrid, InnovationList, StatsGrid, BottomLineQuote });
