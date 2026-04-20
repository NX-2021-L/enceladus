// Lightbox carousel for platform screenshots.
const { useEffect: useEffectC } = React;

function Carousel({ open, images, index, onPrev, onNext, onClose }) {
  useEffectC(() => {
    if (!open) return;
    const h = (e) => {
      if (e.key === 'Escape') onClose();
      if (e.key === 'ArrowRight') onNext();
      if (e.key === 'ArrowLeft') onPrev();
    };
    document.addEventListener('keydown', h);
    document.body.style.overflow = 'hidden';
    return () => { document.removeEventListener('keydown', h); document.body.style.overflow = ''; };
  }, [open, onClose, onNext, onPrev]);

  if (!open) return null;
  const s = images[index];
  return (
    <div className="carousel-overlay" role="dialog" aria-modal="true" onClick={e => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="carousel-inner">
        <button className="carousel-close" onClick={onClose} aria-label="Close">×</button>
        <button className="carousel-arrow carousel-prev" onClick={onPrev} aria-label="Previous">‹</button>
        <div className="carousel-image-wrapper">
          <img id="carousel-img" src={s.src} alt={s.caption} />
          <p className="carousel-caption">{s.caption}</p>
        </div>
        <button className="carousel-arrow carousel-next" onClick={onNext} aria-label="Next">›</button>
        <div className="carousel-counter">{index + 1} / {images.length}</div>
      </div>
    </div>
  );
}

Object.assign(window, { Carousel });
