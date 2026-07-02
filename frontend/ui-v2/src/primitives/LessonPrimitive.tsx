import { Lightbulb } from 'lucide-react'
import type { Lesson } from '../types/records'
import { MetaRow, Metric, PrimitiveCard, Prose } from '../components/PrimitiveCard'

export function LessonPrimitive({ record }: { record: Lesson }) {
  return (
    <PrimitiveCard
      recordId={record.lesson_id}
      kindLabel="Lesson"
      title={record.title}
      status={record.status}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 'var(--space-2)',
          marginBottom: 'var(--space-3)',
          color: 'var(--knowledge)',
        }}
      >
        <Lightbulb size={16} strokeWidth={1.5} />
        <span
          style={{
            fontFamily: 'var(--font-heading)',
            fontSize: 'var(--text-xs)',
            textTransform: 'uppercase',
            letterSpacing: 'var(--tracking-label)',
          }}
        >
          {record.category}
        </span>
      </div>
      <Prose>{record.observation}</Prose>
      <blockquote
        style={{
          borderLeft: '4px solid var(--knowledge)',
          margin: 'var(--space-4) 0',
          padding: 'var(--space-4) var(--space-5)',
          fontStyle: 'italic',
          background: 'rgba(138, 140, 181, 0.08)',
          borderRadius: 'var(--radius-md)',
          color: 'var(--fg)',
        }}
      >
        {record.insight}
      </blockquote>
      <MetaRow label="Confidence">
        <Metric>{record.confidence.toFixed(2)}</Metric>
      </MetaRow>
      <MetaRow label="Resonance">
        <Metric>{record.resonance_score.toFixed(2)}</Metric>
      </MetaRow>
      <MetaRow label="Provenance">{record.provenance}</MetaRow>
    </PrimitiveCard>
  )
}
