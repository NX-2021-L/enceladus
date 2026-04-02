import { useParams, Link } from 'react-router-dom'
import { useLessons } from '../hooks/useLessons'
import { StatusChip } from '../components/shared/StatusChip'
import { PillarScoreChart } from '../components/shared/PillarScoreChart'
import { LinkedText } from '../components/shared/LinkedText'
import { MarkdownRenderer } from '../components/shared/MarkdownRenderer'
import { HistoryFeed } from '../components/shared/HistoryFeed'
import { timeAgo } from '../lib/formatters'

export default function LessonDetailPage() {
  const { lessonId } = useParams<{ lessonId: string }>()
  const { lessons, isLoading } = useLessons()

  const lesson = lessons.find((l) => l.lesson_id === lessonId)

  if (isLoading) {
    return <div className="p-4 text-slate-400">Loading...</div>
  }
  if (!lesson) {
    return <div className="p-4 text-slate-400">Lesson not found: {lessonId}</div>
  }

  return (
    <div className="p-4 max-w-3xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2 mb-1">
          <Link to="/feed" className="text-xs text-blue-400 hover:text-blue-300">&larr; Feed</Link>
          <span className="text-xs text-slate-600">/</span>
          <span className="text-xs text-slate-500">{lesson.project_id}</span>
        </div>
        <div className="flex items-center gap-2 mb-2">
          <span className="text-sm font-mono text-purple-400">{lesson.lesson_id}</span>
          <StatusChip status={lesson.status} />
          {lesson.category && (
            <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-purple-500/20 text-purple-400">
              {lesson.category}
            </span>
          )}
        </div>
        <h1 className="text-xl font-semibold text-slate-100">{lesson.title}</h1>
        <div className="flex items-center gap-3 mt-2 text-xs text-slate-500">
          {lesson.provenance && <span>Provenance: {lesson.provenance}</span>}
          {typeof lesson.confidence === 'number' && <span>Confidence: {(lesson.confidence * 100).toFixed(0)}%</span>}
          {lesson.lesson_version && <span>v{lesson.lesson_version}</span>}
          {lesson.updated_at && <span>{timeAgo(lesson.updated_at)}</span>}
        </div>
      </div>

      {/* Constitutional Scores */}
      {lesson.pillar_scores && (
        <section className="bg-slate-800 rounded-lg p-4">
          <h2 className="text-sm font-semibold text-slate-300 mb-3">Constitutional Pillar Scores</h2>
          <PillarScoreChart
            pillarScores={lesson.pillar_scores}
            pillarComposite={lesson.pillar_composite ?? 0}
            resonanceScore={lesson.resonance_score ?? 0}
          />
        </section>
      )}

      {/* Observation */}
      {lesson.observation && (
        <section>
          <h2 className="text-sm font-semibold text-slate-300 mb-2">Observation</h2>
          <div className="bg-slate-800 rounded-lg p-4 text-sm text-slate-300">
            <MarkdownRenderer content={lesson.observation} />
          </div>
        </section>
      )}

      {/* Insight */}
      {lesson.insight && (
        <section>
          <h2 className="text-sm font-semibold text-slate-300 mb-2">Insight</h2>
          <div className="bg-slate-800 rounded-lg p-4 text-sm text-slate-300">
            <MarkdownRenderer content={lesson.insight} />
          </div>
        </section>
      )}

      {/* Evidence Chain */}
      {lesson.evidence_chain && lesson.evidence_chain.length > 0 && (
        <section>
          <h2 className="text-sm font-semibold text-slate-300 mb-2">
            Evidence Chain ({lesson.evidence_chain.length})
          </h2>
          <div className="bg-slate-800 rounded-lg p-4 space-y-1">
            {lesson.evidence_chain.map((eid, i) => (
              <div key={i} className="text-sm">
                <LinkedText text={eid} />
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Extensions Timeline */}
      {lesson.extensions && lesson.extensions.length > 0 && (
        <section>
          <h2 className="text-sm font-semibold text-slate-300 mb-2">
            Extensions ({lesson.extensions.length})
          </h2>
          <div className="bg-slate-800 rounded-lg p-4 space-y-3">
            {lesson.extensions.map((ext, i) => (
              <div key={i} className="border-l-2 border-purple-500/30 pl-3">
                <div className="text-xs text-slate-500 mb-1">
                  {ext.timestamp && timeAgo(ext.timestamp)}
                  {ext.provider && ` \u2014 ${ext.provider}`}
                </div>
                <div className="text-sm text-slate-300">
                  <LinkedText text={ext.description} />
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Governance Proposal */}
      {lesson.governance_proposal && (
        <section>
          <h2 className="text-sm font-semibold text-slate-300 mb-2">Governance Proposal</h2>
          <div className="bg-amber-900/20 border border-amber-500/30 rounded-lg p-4 text-sm text-amber-200">
            <MarkdownRenderer content={lesson.governance_proposal} />
          </div>
        </section>
      )}

      {/* Analysis Reference */}
      {lesson.analysis_reference && (
        <section>
          <h2 className="text-sm font-semibold text-slate-300 mb-2">Analysis Reference</h2>
          <div className="text-sm text-slate-400">
            <LinkedText text={lesson.analysis_reference} />
          </div>
        </section>
      )}

      {/* Related Items */}
      {(lesson.related_task_ids?.length > 0 || lesson.related_issue_ids?.length > 0 || lesson.related_feature_ids?.length > 0) && (
        <section>
          <h2 className="text-sm font-semibold text-slate-300 mb-2">Related Items</h2>
          <div className="bg-slate-800 rounded-lg p-4 space-y-1 text-sm">
            {[...lesson.related_task_ids, ...lesson.related_issue_ids, ...lesson.related_feature_ids].map((id, i) => (
              <div key={i}><LinkedText text={id} /></div>
            ))}
          </div>
        </section>
      )}

      {/* History */}
      {lesson.history && lesson.history.length > 0 && (
        <section>
          <h2 className="text-sm font-semibold text-slate-300 mb-2">History</h2>
          <HistoryFeed history={lesson.history} />
        </section>
      )}
    </div>
  )
}
