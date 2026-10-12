/** DVP-TSK-A24: Settings > Notifications on @io-kit/notify (enable push, kinds, minimum risk, detail level). */
import { NotificationSettings } from '@io-kit/notify/react'
import '@io-kit/notify/notify.css'
import { PageHeader } from '../components/PageHeader'
import { useDocumentTitle } from '../hooks/useDocumentTitle'
import { escalationCatalog } from '../notifications/escalationCatalog'
import { notifyApi } from '../notifications/notifyApi'
import type { NotifyApi } from '@io-kit/notify'

export function NotificationSettingsRoute({ api = notifyApi }: { api?: NotifyApi }) {
  useDocumentTitle('Notifications')
  return (
    <div className="ev2-page">
      <PageHeader title="Notifications" description="Choose which escalations push to this device, the minimum risk, and how much the notification reveals." />
      <NotificationSettings catalog={escalationCatalog} api={api} />
    </div>
  )
}
