# Enceladus passkey enrollment and recovery runbook (DVP-FTR-105, ruling E41-R3)

Owner: io. Applies to the Enceladus Cognito pool `us-east-1_b2D0V3E1k`, which serves enceladus.jreese.net and enceladus-gamma.jreese.net through managed login at `auth.enceladus.jreese.net`.

## 1. What a passkey does here

- **Sign-in.** The pool allows two first factors: `PASSWORD` and `WEB_AUTHN`. It runs on the ESSENTIALS tier, with MFA OFF. WebAuthn user verification is set to **required**, and the relying party is `auth.enceladus.jreese.net`. Managed login (v2, choice-based) offers the passkey on every sign-in.
- **Step-up for high and critical gates.** The escalations cockpit sends you to a fresh managed-login sign-in (`prompt=login`, `max_age=0`). The hub accepts the decision only when the ID token's `auth_time` is no more than 300 s old and matches the `cognito_max_age` proof (`ESCALATION_STEP_UP_MAX_AGE_SECONDS`). The decision log records `auth_method`, `auth_time`, `assurance=aal2` and `proof_method=cognito_max_age`.
- **Limitation (E41-R3).** Cognito emits no `amr`/`acr` claim, even for a user-verified passkey sign-in. This was observed on 2026-10-14 at 00:43:14Z and 01:05:49Z, with the `auth_claims` log line from `auth_refresh`. The hub therefore cannot tell a passkey sign-in from a password sign-in. The enforced rule is fresh managed-login re-auth, and the passkey is the factor managed login offers. The decision log records `auth_method=interactive_human`, never `webauthn`.

## 2. Enroll (do this on at least two authenticators)

1. Open enceladus.jreese.net, open the navigation menu (sidebar), and choose **Add a passkey**, which sits between App refresh and Log out.
2. The PWA sends you through a fresh managed-login sign-in first, then to managed login `/passkeys/add`. Approve the platform prompt (Touch ID, Face ID, Windows Hello, or a security key).
3. You return to the PWA. A notice confirms the result (DVP-TSK-B24 `PasskeyResultNotice`). If the sign-in expired first, choose **Add a passkey** again.
4. Repeat on a second authenticator, such as a second device or a hardware key. Each enrollment adds a credential, and the pool allows more than one per user. A synced passkey (iCloud Keychain, Google Password Manager or 1Password) counts as one credential that is available on all of that provider's devices.

Passkeys belong to this pool and this RP. A passkey for think (`auth.thepup.io`) or coach does not work here, and the reverse is also true.

## 3. Recover (lost or unavailable passkey)

1. On the managed-login page, choose **sign in with password** instead of the passkey. PASSWORD stays an allowed first factor on purpose, so it is the break-glass path.
2. If the password is also lost, use **Forgot password**. Account recovery goes to the verified email first, then the verified phone.
3. Once you are signed in, open the navigation menu and choose **Add a passkey** to enroll a replacement. Then remove the lost credential from the authenticator's own manager (Apple Passwords, Google Password Manager or 1Password).
4. Gate decisions keep working throughout, because a fresh password sign-in also satisfies the 300 s rule. That is the E41-R3 limitation, not a downgrade. Every decision still records its `auth_time` and assurance in the decision log, so a decision made during a recovery window can be audited by time.

## 4. Operator notes (product-lead)

- To check the pool posture, run `aws cognito-idp describe-user-pool --region us-east-1 --user-pool-id us-east-1_b2D0V3E1k`. Look at `Policies.SignInPolicy.AllowedFirstAuthFactors` and `UserPoolTier`. Use `get-user-pool-mfa-config` for the WebAuthn user-verification setting.
- Before the 2026-10-14 change, the pool's MFA config was WebAuthn user verification `preferred` with FactorConfiguration `SINGLE_FACTOR`.
- **Never** remove `PASSWORD` from `AllowedFirstAuthFactors` while only one passkey is enrolled.
- To read what the token carries on a real sign-in, use the `auth_refresh` Lambda log line `{"event":"auth_claims", ...}`. It gives the path (callback or refresh), amr, acr, auth_time and token_use, and contains no token material.

## 5. When to revisit

If Cognito starts emitting `amr` for WEB_AUTHN (for example on a later tier or feature), the hub's reserved `webauthn` verifier slot (`_STEP_UP_RESERVED_METHODS`) is where a passkey-only rule plugs in, with no call-site changes (DVP-FTR-105 AC1 contract). That would reopen DVP-FTR-105 AC5 (passkey-required policy, logged per-gate downgrade).

Tracker: DVP-FTR-105, DVP-TSK-983/984/985. Docstore copy: DOC-C9CD70F7C9ED.
