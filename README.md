# Shield Passkey MFA (WebAuthn)

A drop-in set of Shield **Actions**, controllers, and views that add
passkey (WebAuthn/FIDO2) based MFA to a CodeIgniter Shield app - the
actual cryptography is entirely delegated to
[`web-auth/webauthn-lib`](https://github.com/web-auth/webauthn-lib),
not reimplemented here.

Built as the passkey counterpart to the `shield-totp-mfa` package in
this same series, reusing every architectural lesson learned building
that one:

- **`PasskeyMfa`** - the `'login'` action. Verification only.
- **`PasskeyActivator`** - the `'register'` action. Optional setup
  during signup, with a "skip for now" link.
- **`PasskeySettingsController`** - self-service add/rename/remove,
  any time, for existing users.

Unlike a single TOTP secret, a user can register **several** passkeys
(phone, laptop, a hardware key as backup), so credentials are stored in
their own table (`auth_passkey_credentials`) - a genuine list, closer
in shape to `shield-totp-mfa`'s remembered-devices table than to its
single-secret model.

**Deliberately out of scope:** "remember this device" and "step-up auth
for sensitive pages" aren't reimplemented here - both could be added
following the exact same pattern as `shield-totp-mfa`'s
`RememberedDeviceModel`/`RequireFreshTotp` filter, if wanted. This
package's job is the actually-new part: the WebAuthn integration
itself.

## Read this before anything else: version sensitivity

`web-auth/webauthn-lib` has changed its core setup API significantly
across major versions - PSR-7-based request handling and a
`PublicKeyCredentialLoader` class in v3.x, deprecated in favor of a
Symfony Serializer approach in v4.8, and removed entirely in v5.0 in
favor of `Webauthn\CeremonyStep\CeremonyStepManagerFactory`. This
package was written against the confirmed-current v5.x shape (verified
against the library's own current documentation, not assumed from
memory), all isolated into one file: `src/Libraries/WebauthnFactory.php`.
That file's own doc comment has the full explanation and a checklist -
read it before relying on this package, especially if
`composer show web-auth/webauthn-lib` shows something other than a 5.x
version.

A mismatch here fails loudly (a PHP `TypeError`), not silently - which
is the good news. The more important thing this can't protect you from
automatically: **actually run a real registration and a real login
through a real browser and authenticator before trusting this in
production.** This is the one package in this series where "the code
looks right" is meaningfully less reassuring than usual, given how
cryptography-heavy the actual verification is - there's no equivalent
here to TOTP's RFC 6238 test vectors to check the math against.

## Every synced passkey login used to fail verification - fixed

**Fixed in the current version - update immediately if you're on an
older copy; this affects every login, not an edge case.** An earlier
version of `WebauthnFactory` used `web-auth/webauthn-lib`'s own
default signature counter checker
(`Webauthn\Counter\ThrowExceptionIfInvalid`) unmodified. That default
hard-rejects a login the moment the signature counter fails to
strictly increase between attempts.

Passkeys synced via Chrome's or Edge's or Safari's own built-in,
cloud-based passkey managers (iCloud Keychain, Google Password
Manager, Windows Hello's own cloud sync) report a signature counter of
**0 on every single authentication, permanently** - this is
intentional, spec-compliant behavior, not a bug in those platforms.
The W3C WebAuthn specification itself says explicitly: if both the
stored and returned counters are 0, the authenticator does not support
a counter, and the check should be skipped entirely - a
strictly-increasing counter has no coherent meaning for a credential
that can legitimately be used from several independently-synced
devices at once, which is the whole point of a synced passkey. The
library's own default checker doesn't apply that exception, so
`stored=0, new=0` was treated as "counter did not increase" and
rejected - meaning **every login with a synced passkey failed
verification, unconditionally**, regardless of how many credentials a
user had registered or which device/browser they used. From the
user's side, this looked exactly like: the browser's own passkey
prompt appears and is completed successfully, but the page just
reloads back to the login screen, silently.

`WebauthnFactory::assertionValidator()` now wires in
`SyncedPasskeyCounterChecker` instead - implementing the W3C's own
guidance directly: both counters at 0 is accepted (authenticator
doesn't support one), a genuinely non-zero counter is still required
to strictly increase (preserving the counter's real purpose - detecting
a cloned hardware security key, for the credentials where that check
actually means something). See that class's own doc comment for the
full detail, and `SyncedPasskeyCounterCheckerTest` for coverage of this
logic in isolation (this specific piece, unlike most of this package,
has no cryptography dependency, so it's fully testable without a real
browser).

**A follow-up fix, confirmed against a real fatal error on a real
app:** the first version of `SyncedPasskeyCounterChecker` type-hinted
`Webauthn\PublicKeyCredentialSource` and called `->getCounter()`,
which caused an immediate `Fatal error: Declaration ... must be
compatible with Webauthn\Counter\CounterChecker::check(Webauthn\CredentialRecord
$credentialRecord, int $currentCounter): void` on any installed
version where the interface itself expects the newer type. Confirmed
via `web-auth/webauthn-lib`'s own official documentation:
`PublicKeyCredentialSource` was renamed to `CredentialRecord` in
v5.3.0 (the old name still exists, as a deprecated subclass, for
backward compatibility - removed entirely in v6.0), and the counter is
read as a direct property (`->counter`), not a method call. Both are
fixed now - see that class's own doc comment for the full account.

## The two gotchas that will bite you before anything else does

1. **`$rpId` must be your app's real domain, exactly.** No scheme
   (`https://`), no port, no trailing slash - just the domain
   (`example.com`), or a registrable parent of the domain serving your
   app (`example.com` also covers `app.example.com`). Get this wrong
   and every ceremony fails outright, not gracefully - the browser
   enforces this strictly as a core WebAuthn security property, it
   isn't just a label you're free to make up.

2. **WebAuthn requires either HTTPS or `localhost`, with no
   exceptions.** Testing over plain HTTP on anything other than
   `localhost` itself (including `127.0.0.1`, and including a `.local`
   or `.test` domain some other package in this series used for local
   development) will not work - the browser refuses to run WebAuthn
   ceremonies at all outside a secure context. Use a real `localhost`
   URL, or set up HTTPS (even a self-signed cert) for local testing on
   any other hostname.

## A passkey created on one device doesn't automatically work everywhere

This isn't a bug in this package - it's a well-documented, industry-wide
property of how passkeys actually work, and it's confirmed to catch
real users in real deployments, so it's worth understanding before
anyone hits it in production.

Passkey syncing depends entirely on the platform ecosystem it was
created in - Apple's iCloud Keychain, Google Password Manager, and
Microsoft's own passkey provider all sync within themselves, but **not**
across each other. A passkey created in Chrome on a Mac (synced via
iCloud Keychain or Google Password Manager) will not simply appear when
that same person opens Edge on a Windows machine - that's a different
platform ecosystem entirely, with no passkey registered there at all.
If a user's *only* enrolled MFA method is a passkey, and they're on a
device/browser combination that was never used to register one, they
can be genuinely locked out - unable to complete their existing
challenge, and (per WebAuthn's own security model) unable to add a new
passkey without first being logged in.

### The workaround, today

1. On whichever device/browser combination **does** have a working
   passkey (or any other enrolled MFA method), log in and switch your
   2FA method away from passkey - if you're using
   `shield-mfa-dispatcher`, its settings page lets you do this; see
   that package's README for switching methods programmatically if
   you're not using the dispatcher.
2. On the **new** device/browser combination, log in using that other
   method, then visit `account/passkeys` (this package's own settings
   page - see "Self-service enable/disable" earlier in this README)
   and add a passkey from there. That device/browser now has its own,
   independent passkey registered, alongside whichever one(s) already
   existed.

### The more robust fix, not yet built

Every source on passkey deployment converges on the same real answer
to this: **recovery codes** - single-use backup codes generated at
enrollment time, method-agnostic, specifically for "I have no access
to my usual method right now." This is a genuinely substantial,
separate feature (secure generation, hashed storage, single-use
validation, a UI to display/download/regenerate codes, and a "use a
recovery code instead" link on the challenge page) that doesn't exist
in this package - or anywhere in this series - yet. If losing access to
your only enrolled method is a real risk for your users, plan around
the workaround above until that exists, and consider encouraging users
to enroll a passkey on more than one device from the start (this
package's own settings page already supports multiple credentials per
user - `account/passkeys` isn't limited to one).

## What's in the box

```
src/
  Assets/passkey-early-auth.js           <- reference JS for the optional "trigger a passkey
                                             prompt on email blur" feature - not auto-loaded
  Authentication/Actions/
    PasskeyMfa.php                       <- 'login' action: verification only
    PasskeyActivator.php                 <- 'register' action: optional setup at signup
  Commands/Setup.php                     <- `php spark passkey-mfa:setup`
  Config/PasskeyMfa.php                  <- RP name/ID, challenge TTL, view overrides
  Controllers/
    PasskeyActivatorController.php       <- handles PasskeyActivator's "skip for now" link
    PasskeySettingsController.php        <- self-service add/rename/remove
    PasskeyStepUpController.php          <- step-up challenge page
    PasskeyEarlyAuthController.php       <- optional login-page-blur passkey prompt endpoints
  Database/Migrations/..._CreateAuthPasskeyCredentials.php
  Filters/RequireFreshPasskey.php        <- step-up auth filter for sensitive routes
  Language/en/PasskeyMfa.php
  Libraries/
    Base64Url.php                        <- RFC 4648 base64url, self-contained
    WebauthnFactory.php                  <- builds the webauthn-lib services - THE version-sensitive file
    SyncedPasskeyCounterChecker.php       <- fixes a confirmed bug in the library's own default
                                             signature counter check for synced passkeys
    PasskeyIdentityStore.php             <- shared registration/verification orchestration
    CompletesPendingAction.php           <- shared "finish this pending action" trait
  Models/PasskeyCredentialModel.php
  Views/
    passkey_activator_enroll.php         <- registration ceremony + skip (registration)
    passkey_mfa_verify.php               <- authentication ceremony (login)
    passkey_settings_index.php           <- list/rename/remove
    passkey_settings_enroll.php          <- registration ceremony (self-service)
    passkey_step_up.php                  <- authentication ceremony (step-up)
routes-snippet.php                       <- routes to add by hand
```

## Installation

### Option A - via Composer (recommended)

1. `composer require cloudrepublic/shield-passkey-mfa web-auth/webauthn-lib`.
2. Run the setup command - publishes `Config/PasskeyMfa.php` and
   `Language/en/PasskeyMfa.php` into your app:

   ```
   php spark passkey-mfa:setup
   ```

   The migration is **not** copied anywhere - see step 4.

### Option B - manual drop-in

1. Copy `src/` into your app (e.g. `app/ThirdParty/PasskeyMfa/src`),
   register the `PasskeyMfa` namespace in `app/Config/Autoload.php`,
   and separately `composer require web-auth/webauthn-lib` (this one
   genuinely needs Composer either way - it isn't something reasonable
   to vendor by hand).
2. Copy `Config/PasskeyMfa.php` to `app/Config/PasskeyMfa.php`, and
   `Language/en/PasskeyMfa.php` to `app/Language/en/PasskeyMfa.php`.

### Either way, finish with these

3. **Set `$rpName` and `$rpId`** in `app/Config/PasskeyMfa.php` (or via
   `.env`) - see the gotchas above for `$rpId` specifically.

4. **Run the migration - no copying needed**, exactly like
   `shield-totp-mfa`'s migration (see that package's README for the
   full story on why copying it instead causes real problems):

   ```
   php spark migrate --all
   ```

   (or `php spark migrate -n PasskeyMfa` to target just this package).

5. **Register the action(s)** in `app/Config/Auth.php`. Login
   verification is required; registration-time setup is optional:

   ```php
   public array $actions = [
       'register' => \PasskeyMfa\Authentication\Actions\PasskeyActivator::class, // optional
       'login'    => \PasskeyMfa\Authentication\Actions\PasskeyMfa::class,
   ];
   ```

   If you don't want a passkey step at signup, leave `'register' => null`.

6. **Add the routes** from `routes-snippet.php` to
   `app/Config/Routes.php`, and link to `account/passkeys` from
   wherever your account settings page lives. If you registered
   `PasskeyActivator` in step 5, **add its "skip" route by default** -
   the enrollment view always renders a "skip for now" link, regardless
   of whether this route exists (a missing route makes the view detect
   this and simply hide the link, rather than throwing when the very
   first user registers), so only leave it out if you deliberately
   don't want "skip" offered at all (e.g. because MFA is mandatory for
   everyone via `shield-mfa-dispatcher`'s
   `$required`/`$requiredMethodsForGroups`).

7. **Actually test it, in a real browser, before production.** See
   the version-sensitivity section above.

## Browser support for the client-side JavaScript

Every view uses `PublicKeyCredential.parseCreationOptionsFromJSON()` /
`.parseRequestOptionsFromJSON()` and `credential.toJSON()` - the
WebAuthn Level 3 JSON helpers (Chrome 122+, Safari 17.4+, and current
Firefox). These exist specifically so a spec-compliant server library
and a spec-compliant browser can agree on a JSON shape without any
hand-written glue code converting between base64url strings and
`ArrayBuffer`s - which is what every *older* WebAuthn tutorial's
JavaScript is full of, and is exactly the kind of fiddly, easy-to-get-
subtly-wrong code this package tries to avoid needing.

If your users are on browsers old enough to lack these methods,
replace the relevant block in each view's `<script>` with the classic
manual conversion pattern (widely documented at
[webauthn.guide](https://webauthn.guide/)) instead.

`src/Assets/passkey-early-auth.js` (the optional login-page-blur
feature) additionally relies on `navigator.credentials.get()`'s own
`signal` option (an `AbortController`/`AbortSignal`, used to cancel an
in-flight ceremony the moment the visitor moves on to the password
field) - confirmed via MDN's own documentation and W3C's own
web-platform-tests as a real, specified, widely-implemented part of
the Credential Management API (the same mechanism libraries like
SimpleWebAuthn use for identical reasons). Precise per-browser version
numbers for this specific option aren't confirmed here the way the
JSON helpers above are - if you need to support unusually old
browsers, test this specifically rather than assuming it's covered by
the same version floor.

## Enrollment used to require a confusing second click - fixed

**Fixed in the current version - update if you're on an older copy.**
`passkey_activator_enroll.php` and `passkey_settings_enroll.php` used
to show a status message ("Passkey created - click below to finish")
after a successful registration ceremony, then require the visitor to
click a *second* button to actually complete enrollment - a button
that shared the exact same label text as the first one, making it look
like nothing had happened. Combined with an explicit "Cancel" link
sitting right next to it (on the settings-page version) or a "skip"
link right below it (on the registration-time version), the whole flow
looked broken - confirmed to cause real users to abandon enrollment
entirely, or need multiple attempts to find the right button to click.

There's no good reason to require a second, manual click at all once
the ceremony has already succeeded - both views now call the form's
own `requestSubmit()` automatically the instant `navigator.credentials.create()`
resolves, so enrollment completes with a single click, the way it
should have from the start.

## Overriding views

Every view is looked up through `Config\PasskeyMfa::$views`, the same
pattern Shield itself uses for `Config\Auth::$views`, and every other
package in this series uses for its own views:

```php
public array $views = [
    'passkey_mfa_verify' => 'App\Views\auth\my_passkey_verify',
    // any key you don't list keeps using this package's default
];
```

Unlike the other packages in this series, a replacement view here
needs to bring its own working WebAuthn JavaScript too, not just
markup - copy the relevant `<script>` block from the default view as a
starting point rather than writing one from scratch.

## Why this needed two identity types, same as `shield-totp-mfa`

Shield decides whether an action is "pending" purely by whether an
identity of `getType()`'s type exists in the database - not by
anything about that identity's state. A permanent credential marker
that's never deleted (the whole point of a passkey) is only safe for
`PasskeyMfa` (login) to check for because enrollment happens somewhere
else entirely (`PasskeyActivator`, or the settings page), using a
*separate*, disposable identity type
(`PasskeyIdentityStore::ID_TYPE_PASSKEY_ACTIVATE`) that Shield's own
pending-check sees during registration instead. This is the exact same
trap - and exact same fix - documented at length in
`shield-totp-mfa`'s README; not repeated here beyond this summary. See
`PasskeyIdentityStore`'s class doc comment for the specifics as they
apply to this package.

## The permanent marker's secret used to collide between any two users - fixed

**Fixed in the current version - update if you're on an older copy,
and this is the most severe bug found across this whole series.** The
permanent `'passkey'` marker described above
(`PasskeyIdentityStore::syncPermanentMarker()`) used to store a
**fixed literal string** (`'n/a'`) as its `secret` column, on the
reasoning that "it's never read, only the marker's existence matters."

That reasoning missed Shield's own `auth_identities` `UNIQUE(type,
secret)` constraint - **not** `(user_id, type, secret)`. Any two users
who both had at least one passkey credential enrolled would both
produce `(type='passkey', secret='n/a')`, an identical pair. Unlike
similar bugs found in this same series (see `shield-whatsapp-mfa`'s
`PhoneNumberStore`, which had two related ones), this one needed no
coincidence and no timing window at all - it's **permanent**, so the
**second person to ever enroll a passkey** in any real, multi-user app
would hit a duplicate-key database error and be unable to complete
registration, indefinitely, not just during a brief window. This
wasn't an edge case; it was close to guaranteed to eventually surface
in any app with more than one user actually adopting passkeys.

Fixed by randomizing the value (`bin2hex(random_bytes(8))`) instead -
the exact same approach this class's own *temporary* activation marker
(`ensureActivationMarker()`, a few lines above `syncPermanentMarker()`
in the source) already used correctly. The marker's existence is still
all that's ever checked by Shield's own pending-logic or by this
package's own `hasEnrolled()`; its content remains genuinely unused,
now just genuinely unique per row too.

## Login completion: `completeLogin()`, not `login()`

Same confirmed-against-Shield-v1.3.0 caveat as every other package in
this series: `completePendingAction()` calls `completeLogin($user)`,
not `login($user)` - see `shield-totp-mfa`'s README for the full
explanation if you hit login issues after upgrading Shield.

## `PasskeyActivator` doubles as a forced-setup step, not just registration

Written purely for registration-time signup, but if you're using
`shield-mfa-dispatcher`'s `Config\MfaDispatcher::$requiredMethodsForGroups`,
this class gets reused unmodified as a login-time forced-setup step too
- see `shield-totp-mfa`'s README (under "Design decisions worth knowing
about") for the full explanation of why `verify()` checks
`$user->active` before activating/redirecting, and why that one check
was all that was needed to make this safe for both contexts.

## If a page loads but shows nothing at all

Same issue as every other package in this series: views must wrap
their content in a section called `'main'`, matching what Shield's own
layout actually renders - already handled correctly in this package's
shipped views, but worth knowing if you write your own.

## Step-up auth for sensitive pages (`RequireFreshPasskey` filter)

Everything above concerns login. This is different: a route **filter**
that forces a fresh passkey challenge before reaching a specific page,
even for a user who's already fully logged in - useful for gating
sensitive actions (updating payment/API settings, changing an email
address, etc.) behind re-confirmed identity, the way Stripe, GitHub,
and AWS all do before letting you touch billing or security settings.
Mirrors `shield-totp-mfa`'s own `RequireFreshTotp` filter exactly - see
that package's README for more detail on the design; the short version
is repeated here.

### Setup

1. Register the filter alias in `app/Config/Filters.php`:

   ```php
   public array $aliases = [
       // ... your existing aliases
       'passkey-fresh' => \PasskeyMfa\Filters\RequireFreshPasskey::class,
   ];
   ```

2. Add the step-up challenge routes from `routes-snippet.php` (already
   included if you copied the whole snippet earlier).

3. Apply it to whichever routes need protecting, alongside your normal
   login-required filter:

   ```php
   $routes->group('admin/billing', ['filter' => ['session', 'passkey-fresh']], static function ($routes) {
       $routes->get('stripe-settings', 'Admin\BillingController::index');
       $routes->post('stripe-settings', 'Admin\BillingController::update');
   });
   ```

That's it - a user reaching `admin/billing/stripe-settings` without a
recent-enough passkey challenge gets sent to a short WebAuthn challenge
page first, then bounced back to where they were headed.

### How freshness works

A timestamp is stashed in session the moment a challenge succeeds.
Subsequent requests to any `passkey-fresh`-protected route within
`$config->stepUpFreshnessSeconds` (default 15 minutes) pass straight
through without asking again; after that window, the next protected
page reached asks again.

### What happens if the user has no passkey registered at all

By default, `RequireFreshPasskey` lets them through - there's nothing
to challenge them with, so the filter doesn't lock them out of a page
they have no way to unlock. If you'd rather force enrollment before
such pages are reachable at all, set:

```php
public bool $stepUpRequiresEnrollment = true;
public string $stepUpEnrollRouteName  = 'passkey-settings-enroll';
```

### This is separate machinery from the login Action, deliberately

`RequireFreshPasskey`/`PasskeyStepUpController` don't touch Shield's
`ActionInterface`/pending-login mechanism at all - they're an ordinary
CodeIgniter filter and controller operating on `auth()->user()`, reusing
`PasskeyIdentityStore::beginAuthentication()`/`completeAuthentication()`
directly (the exact same WebAuthn ceremony the login action itself
uses). See `shield-totp-mfa`'s README for the fuller explanation of why
step-up auth is deliberately kept out of the Action system entirely.

## Optional: trigger a passkey prompt from the login form

Off by default. Several sites (GitHub, Microsoft, and others) trigger
the browser's native passkey prompt as soon as a returning user tabs
away from the email field on the login form - before they've typed
anything into the password field at all. If they have a passkey
registered, they can complete the whole login right there; if not,
nothing happens and they just continue typing their password normally.

### How it works

Two new AJAX (JSON) endpoints, deliberately separate from the login
Action (`PasskeyMfa`) and step-up (`PasskeyStepUpController`) machinery
- the visitor calling these isn't logged in, or even mid-login,
at all, so neither Shield's pending-login state nor an authenticated
session is involved:

- **`POST auth/a/passkey-early/options`** - given an email, returns
  WebAuthn request options if that email has a registered passkey.
  Returns the same `{"available": false}` response whether the email
  doesn't exist at all, or exists but has no passkey - the two cases
  are indistinguishable from the outside, so this can't be used to
  enumerate registered emails.
- **`POST auth/a/passkey-early/verify`** - given the browser's WebAuthn
  response, verifies it against the exact identity the matching
  `options` call issued a challenge for (session-pinned server-side,
  not trusted from anything the client sends at verify time), and logs
  the user in on success.

Both reuse `PasskeyIdentityStore::beginAuthentication()`/`completeAuthentication()`
directly - the identical WebAuthn ceremony every other flow in this
package already uses, just invoked against a user looked up by email
rather than one Shield has already put in a pending or logged-in
state.

Deliberately placed under `auth/a/...` - Shield's own established
convention for its gateway-action routes
(`auth-action-show`/`handle`/`verify`), and also commonly the exact
pattern apps already exclude from any global login-required filter.
See the setup steps below - this matters more than it might look like
it should.

### Setup

1. Set `$enableEarlyAuthentication = true` in `app/Config/PasskeyMfa.php`.

2. Add the two routes from `routes-snippet.php` (already included if
   you copied the whole snippet earlier - they return 404 on their own
   if the config flag above is off, so having them present is harmless
   either way).

3. **Check `app/Config/Filters.php`'s `$globals` for a login-required
   filter** (commonly named `session` or `isLoggedIn`) applied to
   every request. **Confirmed, real issue against a real app:** if such
   a filter is global, its own `'except'` list needs to cover these two
   routes too, or the filter silently redirects them to your login page
   before this controller is ever reached - `fetch()` follows that
   redirect and receives HTML back where JSON was expected, which looks
   like the feature doing nothing at all (no error, no prompt, nothing
   in the console). Placing the routes under `auth/a/...` already
   matches what many Shield apps exclude for Shield's own gateway
   routes - for example:

   ```php
   'session' => ['except' => ['login*', 'register', 'auth/a/*', 'logout']],
   ```

   If your own app excludes something else, or doesn't exclude
   `auth/a/*` specifically, add these two routes to whatever your
   actual exclusion list is instead.

4. Copy `src/Assets/passkey-early-auth.js` into your own login page's
   JavaScript (or adapt the logic inline) - this is a reference
   implementation, not something this package loads automatically
   anywhere. Adjust the four things called out at the top of that
   file to match your actual login form: the email field's selector,
   the password field's selector (used to know when to cancel an
   in-flight passkey prompt - see "Cancelling" in that file's own
   header comment), your app's CSRF token field name
   (`Config\Security::$tokenName` - CodeIgniter's default is
   `csrf_test_name`), and the route paths if you changed the route
   names from the defaults.

5. Test it in a real browser with a real passkey already registered -
   same caveat as everywhere else in this README: "the code looks
   right" is meaningfully less reassuring for anything WebAuthn-shaped
   than for ordinary application code.

### Does this bypass your app's own MFA?

`Config\PasskeyMfa::$earlyAuthenticationIsSufficient` (default `true`)
decides this. A passkey is already a strong, phishing-resistant
credential that's inherently multi-factor (possession of the device +
its own biometric/PIN unlock), verified directly by this app rather
than delegated to a third party - unlike `shield-oauth-login`'s
equivalent toggle (`$triggerMfaAfterSso`, which defaults to **still**
requiring MFA, since an external IdP's own security posture isn't
something this app can verify), treating an early passkey login as
sufficient on its own is a more defensible default here. Set it to
`false` if you'd rather layer your app's own MFA (e.g.
`shield-mfa-dispatcher`) on top regardless - a user who authenticates
this way is then sent to the normal MFA challenge page instead of
straight to your app's post-login destination.

### The reflection-based login completion, and why it's needed here too

When `$earlyAuthenticationIsSufficient` is `false`,
`PasskeyEarlyAuthController::completeLogin()` uses the identical
reflection-based mechanism `shield-oauth-login`'s own
`OAuthLoginController::completeLogin()` needed, for the identical
underlying reason: Shield's own `Session::attempt()` is the only path
that correctly triggers its **private** `setAuthAction()` pending-check
- and `attempt()` requires a password to check, which a visitor at
this point in the flow doesn't have (they haven't submitted the login
form at all yet). There is no public Shield API for "log this
already-verified user in, but still check whether MFA should apply
first." See that method's own doc comment, and `shield-oauth-login`'s
README, for the fuller account of why this approach was needed rather
than a cleaner alternative.

## Tests

**If you're using `shield-mfa-dispatcher`** (or anything else that
makes `Config\Auth::$actions` point at something other than
`PasskeyMfa`/`PasskeyActivator` directly): the confirmed fixes
`shield-totp-mfa` needed for this exact same architecture (session
leakage between test methods, `resetServices()`'s own route-wiping
side effect, and reflection-based pending-state simulation for the
registration-time activator once `'login'` points elsewhere) are
applied here too - see `shield-totp-mfa`'s README and its
`TotpMfaTest`/`TotpActivatorTest` class doc comments for the full,
diagnostic-backed account; not repeated here in full since the
mechanism is identical. `PasskeyMfaTest` and `PasskeyActivatorTest`
have the complete fix; `RequireFreshPasskeyTest`,
`PasskeyStepUpControllerTest`, and `PasskeySettingsControllerTest`
have the defensive `Services::routes()->loadRoutes()` piece only,
since they use `actingAs()` rather than `attempt()` and were never
affected by the session/pending-state issues specifically.

`tests/PasskeyMfa/` covers everything genuinely testable without a
real browser and authenticator: marker sync, ownership checks, JSON
shape, and graceful failure handling. It deliberately does **not**
cover the actual cryptographic verification succeeding - see below.

```
tests/PasskeyMfa/
  Libraries/Base64UrlTest.php                  <- pure codec round-trip, no DB/HTTP
  Libraries/SyncedPasskeyCounterCheckerTest.php <- the fixed counter-check logic, in isolation -
                                                     no cryptography involved, fully covered
  Libraries/PasskeyIdentityStoreTest.php        <- marker sync, ownership, JSON shape, graceful failures,
                                                     and the regression test for the fixed duplicate-key bug
  Authentication/Actions/PasskeyMfaTest.php     <- login action: getType/createIdentity, show() smoke test
  Authentication/Actions/PasskeyActivatorTest.php <- register action: same, plus skip
  Controllers/PasskeySettingsControllerTest.php <- list/rename/remove only (not enroll/confirm)
  Filters/RequireFreshPasskeyTest.php           <- step-up freshness/enrollment logic
  Controllers/PasskeyStepUpControllerTest.php   <- step-up challenge page (show() smoke test,
                                                    graceful verify() failure - not the crypto success path)
  Controllers/PasskeyEarlyAuthControllerTest.php <- login-page-blur endpoints: config-gating,
                                                     email-enumeration safety, graceful verify() failure
```

### Setup

1. Copy `tests/PasskeyMfa` into your app's own `tests/` folder, the
   same way `src/` gets installed - see "Installation" above.
2. Make sure your test database has Shield's own migrations and this
   package's migration applied - `protected $namespace = null;` in
   each test class triggers this automatically, equivalent to
   `php spark migrate --all`, as long as the connection itself works.
3. Run it the same way as the rest of your suite:

   ```
   vendor/bin/phpunit tests/PasskeyMfa
   ```

### Why the actual cryptographic success path isn't tested here

Producing a genuinely valid, correctly-signed WebAuthn registration or
authentication response requires an actual authenticator (a real
device, or a software/virtual one) - there's no equivalent here to
`shield-totp-mfa`'s RFC 6238 test vectors, since WebAuthn's signatures
are tied to a real private key that only ever exists inside an
authenticator, by design. Faking one to make `completeRegistration()`/
`completeAuthentication()` return `true` isn't something this test
suite attempts.

What IS tested instead, and is genuinely valuable:

- **Marker sync** (`testRemovingTheLastCredentialRemovesThePermanentMarker`
  and friends) - the exact mechanism that had a real, hard-to-find bug
  in `shield-totp-mfa`'s own history, so it's worth covering thoroughly
  here too.
- **Ownership checks** - one user can never rename or remove another
  user's credential, at both the store level and through the
  controller.
- **`beginRegistration()`/`beginAuthentication()` actually running at
  all.** These exercise real `web-auth/webauthn-lib` object
  construction and serialization - not the verification step, but
  enough that if `WebauthnFactory`'s setup is wrong for your installed
  library version (see that file's own doc comment for how much this
  API has moved across versions), these tests are where that surfaces,
  not silently later during an actual user's registration attempt.
- **Graceful failure** - `completeRegistration()`/`completeAuthentication()`
  return `false` rather than throwing for a missing challenge or
  garbage input, which `PasskeyMfaTest`/`PasskeyActivatorTest` confirm
  end-to-end through `verify()` as well.

**Before relying on this package in production, the one thing this
test suite cannot substitute for is registering and logging in with a
real browser and a real authenticator at least once.** This is stated
plainly rather than implied, since "the tests pass" would otherwise be
easy to over-read as "the cryptography works."
