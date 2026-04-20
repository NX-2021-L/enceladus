// Floating CTA strip — bottom-left diamonds.

function FloatStrip({ onOpenCarousel }) {
  return (
    <div className="float-strip">
      <button onClick={onOpenCarousel} className="site-float" aria-label="View Platform Screenshots">
        ◆ View Platform Screenshots
      </button>
      <a href="#" onClick={e => e.preventDefault()} className="site-float" aria-label="Architecture Documentation">
        ◆ Architecture Documentation
      </a>
    </div>
  );
}

Object.assign(window, { FloatStrip });
