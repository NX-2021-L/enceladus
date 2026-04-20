// Footer — teal top rule, mono dust copyright, inline links.

function Footer() {
  const year = new Date().getFullYear();
  return (
    <footer className="site-footer">
      <p>Copyright © J Reese 2002–{year} · Enceladus v3.0 · April 2026</p>
      <div className="footer-links">
        <a href="#">linkedin</a> · <a href="#">resume</a> · <a href="#">home</a>
      </div>
    </footer>
  );
}

Object.assign(window, { Footer });
