// DVP-TSK-861 AC3: the kit's AUTH-C01..C15 suite (client + edge contract + verifier
// against its mock Cognito). auth_refresh's own refresh/manifest wire contract is
// pinned in backend/lambda/auth_refresh/test_kit_edge_contract.py.
import { describe, it } from 'vitest'
import { registerConformance } from '@io-kit/auth/testing'

registerConformance({ describe, it }, { stack: 'enceladus' })
