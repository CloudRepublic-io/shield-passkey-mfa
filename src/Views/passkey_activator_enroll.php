<?= $this->extend(setting('Auth.views')['layout'] ?? 'CodeIgniter\Shield\Views\layout') ?>

<?= $this->section('main') ?>

<h1 class="h3 mb-3"><?= lang('PasskeyMfa.activatorHeading') ?></h1>

<?php if (session('error')) : ?>
    <div class="alert alert-danger"><?= esc(session('error')) ?></div>
<?php endif ?>

<p><?= lang('PasskeyMfa.activatorIntro') ?></p>

<form method="post" action="<?= url_to('auth-action-verify') ?>" id="passkey-form">
    <?= csrf_field() ?>
    <input type="hidden" name="credential" id="passkey-credential-field">

    <div class="mb-3">
        <label for="device_name" class="form-label"><?= lang('PasskeyMfa.deviceNameLabel') ?></label>
        <input
            type="text"
            id="device_name"
            name="device_name"
            class="form-control"
            maxlength="191"
            placeholder="<?= lang('PasskeyMfa.deviceNamePlaceholder') ?>"
        >
    </div>

    <button type="button" id="passkey-start" class="btn btn-primary">
        <?= lang('PasskeyMfa.registerButton') ?>
    </button>
    <p id="passkey-status" class="text-muted small mt-2"></p>
</form>

<?php if (\Config\Services::routes()->reverseRoute('passkey-activator-skip') !== false) : ?>
<form method="post" action="<?= url_to('passkey-activator-skip') ?>" class="mt-2">
    <?= csrf_field() ?>
    <button type="submit" class="btn btn-link p-0">
        <?= lang('PasskeyMfa.skipButton') ?>
    </button>
</form>
<?php endif ?>

<script id="passkey-options-json" type="application/json"><?= $optionsJson ?></script>
<script>
(() => {
    const statusEl = document.getElementById('passkey-status');
    const startBtn = document.getElementById('passkey-start');
    const credentialField = document.getElementById('passkey-credential-field');
    const form = document.getElementById('passkey-form');

    startBtn.addEventListener('click', async () => {
        statusEl.textContent = '';

        if (! window.PublicKeyCredential) {
            statusEl.textContent = 'This browser does not support passkeys.';
            return;
        }

        // CONFIRMED, REAL FIX for a genuinely confusing flow: an
        // earlier version of this script showed a SECOND button
        // (sharing the exact same label text as this one) after a
        // successful ceremony, asking the user to click it to
        // actually finish - identical-looking buttons made it look
        // like nothing had happened, and the nearby "skip"/"cancel"
        // link was the only other clickable thing that stood out,
        // leading users to dismiss the whole flow rather than
        // complete it. There is no good reason to require a second,
        // manual click here at all - the moment the ceremony
        // succeeds, the form now submits itself.
        startBtn.disabled = true;

        const optionsJson = JSON.parse(document.getElementById('passkey-options-json').textContent);

        try {
            // Uses the WebAuthn Level 3 JSON helpers (Chrome 122+,
            // Safari 17.4+) so this package doesn't need to hand-roll
            // base64url <-> ArrayBuffer conversion - a spec-compliant
            // server library and a spec-compliant browser should agree
            // on this JSON shape without any glue code. If your target
            // browsers don't yet support these methods, replace this
            // block with the classic manual conversion pattern (see
            // this package's README).
            const options = PublicKeyCredential.parseCreationOptionsFromJSON(optionsJson);
            const credential = await navigator.credentials.create({ publicKey: options });

            credentialField.value = JSON.stringify(credential.toJSON());
            statusEl.textContent = 'Passkey created - finishing up...';

            // requestSubmit() (rather than form.submit()) still fires
            // the form's own submit event and respects any validation,
            // the same as a real, user-initiated submit would.
            form.requestSubmit();
        } catch (err) {
            statusEl.textContent = 'Could not create a passkey: ' + err.message;
            startBtn.disabled = false;
        }
    });
})();
</script>

<?= $this->endSection() ?>
