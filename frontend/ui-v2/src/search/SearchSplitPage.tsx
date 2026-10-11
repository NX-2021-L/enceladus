import { createContext, useContext, useState, type ReactNode } from 'react'
import { createPortal } from 'react-dom'
import { SplitPage } from '@io-kit/shell/react'
import {
  CollectionSearch,
  ControlsToggle,
  useControlsHidden,
  type CollectionHeaderProps,
  type CollectionSearchProps,
  type ControlsToggleProps,
  type SearchUi,
} from '@io-kit/search-ui'
import { cloudscapeUi, useColorMode } from '@io-kit/search-ui/cloudscape'
import { PageHeader } from '../components/PageHeader'
import './searchSplit.css'

// DVP-TSK-A09 (R16): /feed and /docs on the kit SplitPage. The page header spans every column and is the shared
// PageHeader; CollectionSearch's own header row is replaced by a portal into the SplitPage header slot, so the count
// ("Feed (5,573)") still comes from the search state while the header lives above both columns. Results scroll in
// their own region (scrollResults); the optional secondary pane is its own scroller (ScrollRegion in SplitPage).
//
// DVP-TSK-A12 (io): the tiny "hide toggles" / "show toggles" link sits in that same header, right after the muted
// count. The host owns its state (useControlsHidden, persisted per restoreKey) and renders the kit ControlsToggle
// itself, so CollectionSearch gets controlsToggle={false} (no second link) plus controlsHidden / controlsId, which
// keeps the link's aria-controls pointing at the real control block.
interface HeaderSlotValue {
  slot: HTMLElement | null
  toggle: ControlsToggleProps | null
}
const HeaderSlotContext = createContext<HeaderSlotValue>({ slot: null, toggle: null })

function PortalCollectionHeader({ title, count, refining, actions }: CollectionHeaderProps) {
  const { slot, toggle } = useContext(HeaderSlotContext)
  if (!slot) return null
  const shown = count === undefined ? undefined : `${count.toLocaleString('en-US')}${refining ? ' · refining…' : ''}`
  return createPortal(
    <PageHeader title={title}
      {...(shown ? { count: shown } : {})}
      {...(toggle ? { meta: <ControlsToggle {...toggle} /> } : {})}
      {...(actions ? { actions } : {})}
    />,
    slot,
  )
}

const PAGE_UI: SearchUi = { ...cloudscapeUi, CollectionHeader: PortalCollectionHeader }

export interface SearchSplitPageProps {
  search: Omit<
    CollectionSearchProps,
    'ui' | 'scrollResults' | 'actions' | 'controlsToggle' | 'controlsHidden' | 'defaultControlsHidden' | 'onControlsHiddenChange' | 'controlsId'
  >
  /** Shown at the right of the page header. */
  actions?: ReactNode
  /** The second column (own scroller). Omit for a single-column page. */
  secondary?: ReactNode
  /** Rendered above the header (non-blocking notices). */
  above?: ReactNode
  single?: boolean
  className?: string
  engine?: string
}

export function SearchSplitPage({ search, actions, secondary, above, single, className, engine }: SearchSplitPageProps) {
  useColorMode('dark')
  const [slot, setSlot] = useState<HTMLElement | null>(null)
  const controls = useControlsHidden({ restoreKey: search.restoreKey })
  return (
    <div className={`ev2-fill${className ? ` ${className}` : ''}`} {...(engine ? { 'data-feed-engine': engine } : {})}>
      {above}
      <HeaderSlotContext.Provider value={{ slot, toggle: controls.toggleProps }}>
        <SplitPage
          {...(single ? { className: 'ev2-split--single' } : {})}
          header={<div ref={setSlot} className="ev2-page-header-slot" />}
          scrollPrimary={false}
          primary={
            <CollectionSearch
              ui={PAGE_UI}
              {...search}
              {...(actions ? { actions } : {})}
              controlsToggle={false}
              controlsHidden={controls.hidden}
              onControlsHiddenChange={controls.setHidden}
              controlsId={controls.controlsId}
              scrollResults
            />
          }
          {...(secondary ? { secondary } : {})}
        />
      </HeaderSlotContext.Provider>
    </div>
  )
}
