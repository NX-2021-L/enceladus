// Navbar — sticky top, darkens on scroll past 80px.
const { useState, useEffect } = React;

function Navbar() {
  const [scrolled, setScrolled] = useState(false);
  useEffect(() => {
    const h = () => setScrolled(window.scrollY > 80);
    h();
    window.addEventListener('scroll', h);
    return () => window.removeEventListener('scroll', h);
  }, []);
  return (
    <nav className={`navbar-custom fixed top-0 inset-x-0 z-40 py-3 ${scrolled ? 'scrolled' : ''}`}>
      <div className="container px-5 mx-auto flex items-center justify-between" style={{maxWidth:'1200px'}}>
        <a href="#" className="navbar-brand text-[var(--enc-seafoam)] font-medium text-lg tracking-wide" style={{fontFamily:'Space Grotesk, sans-serif'}}>J Reese</a>
        <ul className="flex gap-6 items-center text-sm" style={{fontFamily:'Inter, sans-serif'}}>
          <li><a className="nav-link text-[var(--enc-starlight)]" href="#" style={{paddingBottom:'4px'}}>home</a></li>
          <li><a className="nav-link text-[var(--enc-starlight)]" href="#" style={{paddingBottom:'4px'}}>links</a></li>
        </ul>
      </div>
    </nav>
  );
}

Object.assign(window, { Navbar });
