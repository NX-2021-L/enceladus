// Hero — full-viewport, moon photo at 0.15 opacity.

function Hero({ data, moonSrc }) {
  return (
    <header className="article-hero">
      <div className="moon-bg" style={{backgroundImage: `url(${moonSrc})`}} />
      <div className="container px-5 mx-auto text-center relative z-10">
        <h1>{data.title}</h1>
        <p className="hero-subtitle">{data.subtitle}</p>
        <p className="hero-byline">{data.byline}</p>
        <div className="hero-badges">
          {data.badges.map(b => (
            <span key={b.label} className={`badge ${b.variant === 'green' ? 'badge-green' : ''}`}>{b.label}</span>
          ))}
        </div>
      </div>
    </header>
  );
}

Object.assign(window, { Hero });
