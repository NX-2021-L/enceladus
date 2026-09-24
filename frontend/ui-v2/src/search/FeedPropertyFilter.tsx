import { useState } from 'react'
import { Autosuggest, PropertyFilter } from '../design-system'
import {
  buildAttributeRegistry,
  suggestPropertyKeys,
  suggestPropertyValues,
} from './attributeRegistry'
import type { PropertyFilterQuery } from './applyPropertyFilter'
import type { LocalSearchRecord } from '../types/search'

type ComposerMode = 'property' | 'value'

interface FeedPropertyFilterProps {
  query: PropertyFilterQuery
  corpus: LocalSearchRecord[]
  onChange: (query: PropertyFilterQuery) => void
}

/**
 * PropertyFilter + attribute autosuggest composer (FTR-127 AC-6/7):
 * type `sta` → pick `status` → Tab → value autosuggest → pill token.
 */
export function FeedPropertyFilter({ query, corpus, onChange }: FeedPropertyFilterProps) {
  const properties = buildAttributeRegistry(corpus)
  const [draft, setDraft] = useState('')
  const [mode, setMode] = useState<ComposerMode>('property')
  const [activeProperty, setActiveProperty] = useState<string | null>(null)

  const propertyOptions =
    mode === 'property'
      ? suggestPropertyKeys(draft, properties).map((p) => ({
          value: p.key,
          description: 'filter property',
          tag: (p.operators ?? ['=']).join(' '),
        }))
      : suggestPropertyValues(activeProperty ?? '', draft, corpus).map((v) => ({
          value: v,
          description: activeProperty ?? '',
        }))

  const addToken = (propertyKey: string, value: string) => {
    onChange({
      ...query,
      tokens: [...(query.tokens ?? []), { propertyKey, operator: '=', value }],
    })
    setDraft('')
    setMode('property')
    setActiveProperty(null)
  }

  const handleComposerChange = (value: string) => {
    if (mode === 'property') {
      const exact = properties.find((p) => p.key === value)
      if (exact) {
        setActiveProperty(exact.key)
        setMode('value')
        setDraft('')
        return
      }
      setDraft(value)
      return
    }

    if (activeProperty) {
      const values = observedValues(activeProperty, corpus)
      if (values.includes(value)) {
        addToken(activeProperty, value)
        return
      }
    }
    setDraft(value)
  }

  const handleTab = (event: React.KeyboardEvent) => {
    if (event.key !== 'Tab' || mode !== 'property') return
    const match = suggestPropertyKeys(draft, properties, 1)[0]
    if (!match) return
    event.preventDefault()
    setActiveProperty(match.key)
    setMode('value')
    setDraft('')
  }

  const placeholder =
    mode === 'property'
      ? 'Add filter — type property (e.g. sta → status), Tab to select'
      : `Value for ${activeProperty} — pick or type`

  return (
    <div className="feed-property-filter">
      <div onKeyDown={handleTab}>
        <Autosuggest
          value={draft}
          options={propertyOptions}
          placeholder={placeholder}
          ariaLabel="Attribute filter composer"
          emptyText={mode === 'property' ? 'No matching properties' : 'No matching values'}
          onChange={(event) => handleComposerChange(event.detail.value)}
        />
      </div>
      <PropertyFilter
        query={query}
        filteringProperties={properties}
        placeholder="Or type field=value and press Enter"
        hint="Filter pills apply above the result cards."
        onChange={(event) => onChange(event.detail)}
      />
    </div>
  )
}

function observedValues(propertyKey: string, corpus: LocalSearchRecord[]): string[] {
  return suggestPropertyValues(propertyKey, '', corpus, 500)
}
