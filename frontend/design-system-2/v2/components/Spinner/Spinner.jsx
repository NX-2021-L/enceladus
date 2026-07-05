// Enceladus v2 · Spinner — orbital ring, never a bouncing loader.
const ev2SpinnerCss = `
@keyframes ev2-spin{to{transform:rotate(360deg)}}
.ev2-spinner{display:inline-block;border-radius:50%;border-style:solid;border-color:rgba(61,155,168,.2);border-top-color:var(--enc-teal,#3D9BA8);animation:ev2-spin .9s linear infinite}
@media (prefers-reduced-motion: reduce){.ev2-spinner{animation-duration:2.5s}}
`;
(function(){if(typeof document!=='undefined'&&!document.getElementById('ev2-spinner-css')){const s=document.createElement('style');s.id='ev2-spinner-css';s.textContent=ev2SpinnerCss;document.head.appendChild(s);}})();

const EV2_SPINNER_SIZES = { small: [14, 2], normal: [20, 2], big: [32, 3], large: [48, 4] };

export function Spinner({ size = 'normal' }) {
  const [px, bw] = EV2_SPINNER_SIZES[size] || EV2_SPINNER_SIZES.normal;
  return <span className="ev2-spinner" role="status" aria-label="Loading" style={{ width: px, height: px, borderWidth: bw }}></span>;
}
