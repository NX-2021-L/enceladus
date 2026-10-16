/** ENC-TSK-Q84: /settings on @io-kit/settings, hosting the Notifications (@io-kit/notify) and Passkeys (@io-kit/auth) sections. */
import { createSettingsRegistry, SettingsPage, type SettingsRegistry } from '@io-kit/settings'
import { NotificationsSection, notificationsSettingsSection } from '@io-kit/notify/react'
import { createCognitoPasskeyAdapter, passkeysSettingsSection } from '@io-kit/auth/passkeys'
import '@io-kit/notify/notify.css'
import '@io-kit/settings/settings.css'
import { PageHeader } from '../components/PageHeader'
import { useDocumentTitle } from '../hooks/useDocumentTitle'
import { buildAddPasskeyUrl } from '../auth/authConfig'
import { escalationCatalog } from '../notifications/escalationCatalog'
import { notifyApi } from '../notifications/notifyApi'

/** Passkey routes are served by auth_refresh at /api/v1/auth/passkeys (same origin); re-auth uses its step-up login entry. */
export function createAppSettingsRegistry(api = notifyApi): SettingsRegistry {
  const registry = createSettingsRegistry()
  registry.register({
    ...notificationsSettingsSection,
    component: () => <NotificationsSection api={api} catalog={escalationCatalog} appName="Enceladus" />,
  })
  const passkeys = passkeysSettingsSection(
    createCognitoPasskeyAdapter({
      apiBase: '/api/v1',
      addPasskeyHref: buildAddPasskeyUrl(),
      loginHref: '/api/v1/auth/login',
    }),
  )
  registry.register(passkeys)
  return registry
}

const appRegistry = createAppSettingsRegistry()

export function SettingsRoute({ registry = appRegistry }: { registry?: SettingsRegistry }) {
  useDocumentTitle('Settings')
  return (
    <div className="ev2-page">
      <PageHeader title="Settings" description="Notifications and sign-in for this device." />
      <SettingsPage registry={registry} />
    </div>
  )
}
