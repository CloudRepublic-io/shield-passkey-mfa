<?= $this->extend(setting('Auth.views')['layout'] ?? 'CodeIgniter\Shield\Views\layout') ?>

<?= $this->section('main') ?>

<h1 class="h3 mb-3"><?= lang('PasskeyMfa.addButton') ?></h1>

<?php if (session('error')) : ?>
    <div class="alert alert-danger"><?= esc(session('error')) ?></div>
<?php endif ?>

<form method="post" action="<?= url_to('passkey-settings-confirm') ?>" id="passkey-form">
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

<a href="<?= url_to('passkey-settings') ?>" class="btn btn-link">Cancel</a>

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

        // CONFIRMED, REAL FIX for a genuinely confusing flow - see
        // passkey_activator_enroll.php's identical comment for the
        // full explanation: an earlier version required a SECOND,
        // identically-labeled button click to actually finish, right
        // next to an explicit "Cancel" link, which made the flow look
        // broken. The form now submits itself the moment the ceremony
        // succeeds - no second click required.
        startBtn.disabled = true;

        const optionsJson = JSON.parse(document.getElementById('passkey-options-json').textContent);

        try {
            const options = PublicKeyCredential.parseCreationOptionsFromJSON(optionsJson);
            const credential = await navigator.credentials.create({ publicKey: options });

            credentialField.value = JSON.stringify(credential.toJSON());
            statusEl.textContent = 'Passkey created - finishing up...';
            form.requestSubmit();
        } catch (err) {
            statusEl.textContent = 'Could not create a passkey: ' + err.message;
            startBtn.disabled = false;
        }
    });
})();
</script>

<?= $this->endSection() ?>
