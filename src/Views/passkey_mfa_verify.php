<?= $this->extend(setting('Auth.views')['layout'] ?? 'CodeIgniter\Shield\Views\layout') ?>

<?= $this->section('main') ?>

<h1 class="h3 mb-3"><?= lang('PasskeyMfa.verifyHeading') ?></h1>

<?php if (session('error')) : ?>
    <div class="alert alert-danger"><?= esc(session('error')) ?></div>
<?php endif ?>

<p><?= lang('PasskeyMfa.verifyIntro') ?></p>

<form method="post" action="<?= url_to('auth-action-verify') ?>" id="passkey-form">
    <?= csrf_field() ?>
    <input type="hidden" name="credential" id="passkey-credential-field">

    <button type="button" id="passkey-start" class="btn btn-primary">
        <?= lang('PasskeyMfa.verifyButton') ?>
    </button>
    <p id="passkey-status" class="text-muted small mt-2"></p>
</form>

<script id="passkey-options-json" type="application/json"><?= $optionsJson ?></script>
<script>
(() => {
    const statusEl = document.getElementById('passkey-status');
    const startBtn = document.getElementById('passkey-start');
    const credentialField = document.getElementById('passkey-credential-field');
    const form = document.getElementById('passkey-form');

    async function runCeremony() {
        statusEl.textContent = '';

        if (! window.PublicKeyCredential) {
            statusEl.textContent = 'This browser does not support passkeys.';
            return;
        }

        const optionsJson = JSON.parse(document.getElementById('passkey-options-json').textContent);

        try {
            // See passkey_activator_enroll.php's script for why the
            // WebAuthn Level 3 JSON helpers are used here instead of
            // manual base64url conversion.
            const options = PublicKeyCredential.parseRequestOptionsFromJSON(optionsJson);
            const credential = await navigator.credentials.get({ publicKey: options });

            credentialField.value = JSON.stringify(credential.toJSON());
            form.submit();
        } catch (err) {
            statusEl.textContent = 'Could not verify your passkey: ' + err.message;
            startBtn.style.display = '';
        }
    }

    startBtn.addEventListener('click', () => {
        startBtn.style.display = 'none';
        runCeremony();
    });
})();
</script>

<?= $this->endSection() ?>
