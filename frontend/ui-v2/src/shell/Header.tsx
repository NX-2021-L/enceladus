import { Link } from '@tanstack/react-router'
import { PanelLeft, Search } from 'lucide-react'
import { useUiStore } from '../store/uiStore'

export function Header() {
  const toggleSidebar = useUiStore((s) => s.toggleSidebar)
  const openCommandPalette = useUiStore((s) => s.openCommandPalette)

  return (
    <header
      style={{
        height: 56,
        flexShrink: 0,
        display: 'flex',
        alignItems: 'center',
        gap: 'var(--space-4)',
        padding: '0 var(--space-5)',
        background: 'var(--bg-surface)',
        borderBottom: 'var(--border-subtle)',
      }}
    >
      <IconButton label="Toggle sidebar" onClick={toggleSidebar}>
        <PanelLeft size={18} strokeWidth={1.5} />
      </IconButton>

      <Link
        to="/"
        style={{
          fontFamily: 'var(--font-heading)',
          fontWeight: 'var(--fw-bold)',
          letterSpacing: 'var(--tracking-wordmark)',
          fontSize: 'var(--text-sm)',
          textTransform: 'uppercase',
          color: 'var(--fg-display)',
          textDecoration: 'none',
        }}
      >
        Enceladus
      </Link>

      <div style={{ flex: 1 }} />

      <button
        type="button"
        onClick={openCommandPalette}
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: 'var(--space-2)',
          padding: 'var(--space-2) var(--space-3)',
          background: 'var(--bg-surface-alt)',
          border: 'var(--border-subtle)',
          borderRadius: 'var(--radius-sm)',
          color: 'var(--fg-muted)',
          fontFamily: 'var(--font-body)',
          fontSize: 'var(--text-sm)',
          cursor: 'pointer',
        }}
      >
        <Search size={14} strokeWidth={1.5} />
        Search records
      </button>
    </header>
  )
}

function IconButton({
  label,
  onClick,
  children,
}: {
  label: string
  onClick: () => void
  children: React.ReactNode
}) {
  return (
    <button
      type="button"
      aria-label={label}
      onClick={onClick}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        justifyContent: 'center',
        width: 34,
        height: 34,
        borderRadius: 'var(--radius-sm)',
        border: 'var(--border-subtle)',
        background: 'transparent',
        color: 'var(--fg)',
        cursor: 'pointer',
      }}
    >
      {children}
    </button>
  )
}
