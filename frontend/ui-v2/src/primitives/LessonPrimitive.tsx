import { Lightbulb } from 'lucide-react'
import type { Lesson } from '../types/records'
import { MetaRow, PrimitiveCard, Prose } from '../components/PrimitiveCard'
import { BarChart, KeyValuePairs } from '../design-system'

const PILLAR_LABELS: { key: keyof Lesson['pillar_scores']; label: string }[] = [
  { key: 'efficiency', label: 'Efficiency' },
  { key: 'human_protection', label: 'Human Protection' },
  { key: 'intention', label: 'Intention' },
  { key: 'alignment', label: 'Alignment' },
]

export function LessonPrimitive({ record }: { record: Lesson }) {
  return (
    <PrimitiveCard
      recordId={record.lesson_id}
      kindLabel="Lesson"
      title={record.title}
      status={record.status}
      recordType="lesson"
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
      <div style={{ marginBottom: 'var(--space-4)' }}>
        <KeyValuePairs
          columns={3}
          items={[
            { label: 'Confidence', value: (record.confidence ?? 0).toFixed(2), mono: true },
            { label: 'Pillar Composite', value: (record.pillar_composite ?? 0).toFixed(3), mono: true },
            { label: 'Resonance', value: (record.resonance_score ?? 0).toFixed(3), mono: true },
          ]}
        />
      </div>
      <BarChart
        title="Constitutional Pillar Scores"
        subtitle="DOC-6EFD5DB32CD8 — efficiency / human_protection / intention / alignment"
        xDomain={PILLAR_LABELS.map((p) => p.label)}
        series={[
          {
            title: 'Pillar Scores',
            data: PILLAR_LABELS.map((p) => record.pillar_scores?.[p.key] ?? 0),
          },
        ]}
        height={220}
      />
      <MetaRow label="Provenance">{record.provenance}</MetaRow>
    </PrimitiveCard>
  )
}
