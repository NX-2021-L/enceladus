# JWT authentication forensics

Over one week in February 2026, Enceladus hit nine separate authentication failures. On the surface they looked unrelated: tracker mutations returning 401, a progressive web app rendering blank after a successful login, sessions stuck in an "expired" loop, project creation failing at the gateway. Debugged one at a time they were a frustrating mess. Stepped back from, they were a small number of recurring patterns — patterns that show up in almost any system built from a serverless backend, a single-page app, and JWT-in-cookies. This is the post-mortem, kept because the patterns generalize.

The actionable fix for the headline bug lives in [how to build Lambda packages for the Linux runtime](../how-to/build-lambda-packages-for-linux.md); the cookie and Cognito specifics live in the [security reference](../architecture/security-frontend.md). This page is about *why* these failures happen and what they have in common.

## The headline: a binary built for the wrong planet

The worst of the nine, because it was the hardest to see, was a cross-platform compilation failure. The deployment packages were built on macOS and run on Lambda's Linux. For pure-Python code that is fine. For libraries with compiled native extensions — `PyJWT` and its `cryptography`/`cffi` dependencies — it is not: macOS produces Mach-O binaries, Linux loads ELF, and the two are not interchangeable.

What made it vicious was the *shape* of the failure. The package was complete; the library was present; nothing failed at build time. At runtime, `import jwt` tried to load a native extension in the wrong format, failed quietly, and set an internal "JWT not available" flag. Every authenticated request then returned 401 — a symptom three layers and one machine boundary away from the cause. The error message even lied: it said the library was missing, when the library was right there, merely unloadable. An engineer reading "JWT library not available" naturally checks whether the library is in the package. It is. The trail goes cold.

The lesson is blunt: **build artifacts for the platform they will run on, and verify the artifact rather than trusting it.** A one-line check that the shipped binaries are ELF, not Mach-O, would have turned a ten-hour incident into a failed build.

## The family resemblance: silent failure at a boundary

Once you see the binary bug clearly, the other eight rhyme with it. Almost every one was a *silent* failure located at a *boundary* between two systems that each individually looked fine.

- **Build environment ↔ runtime.** The binary format mismatch above.
- **API Gateway version ↔ cookie parser.** A newer gateway delivers cookies in a structured `cookies` array rather than only a `Cookie` header. Code that parsed only the header silently saw no token and reported "not logged in" for users who were.
- **Browser cache ↔ live state.** A service worker cached pre-login application state and auth-required paths, so a freshly authenticated user was served a stale, logged-out shell.
- **Cookie scope ↔ request path.** A refresh-token cookie scoped to one narrow path, and a too-strict `SameSite`, meant the credential simply was not attached to the requests that needed it.
- **Query path ↔ mutation path.** The client handled 401s on data reads but not on data writes, so an expired session recovered gracefully on navigation and dead-ended on the first mutation.
- **Cognito config ↔ deployed env vars.** A user-pool identifier mismatch caused tokens to be rejected — silently, because a token signed by the "wrong" pool is not an error, just an invalid token.

None of these announced themselves where the problem was. Each presented as a generic 401 or a blank page, far from the actual fault. That is the real subject of this forensics: not nine bugs, but one failure *mode* — boundaries that fail quietly and report their symptoms somewhere else.

## What it changed

The durable response was not nine point-fixes; it was a posture. **Fail loud and early:** validate that the JWT library actually loaded at module import, and have the function refuse to serve rather than dribble out 401s if it did not. **Make both sides of every boundary explicit:** parse cookies from both the header and the structured array; handle auth errors on both the read and write paths; keep the browser's cached notion of "logged in" subordinate to the live one. **Verify, don't trust:** check the shape of build artifacts and the match between deployed configuration and the code's expectations, as part of shipping rather than after an outage.

That a week of disparate, maddening symptoms collapsed into a single principle — *auth fails silently at boundaries, so instrument the boundaries and fail loudly* — is the reason this incident was worth writing down. It is also a small example of the platform's broader bet: that the way to keep a complex system trustworthy is to make its failure modes legible, early, and close to their cause.
