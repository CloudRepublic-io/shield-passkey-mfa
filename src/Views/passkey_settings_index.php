<?= $this->extend(setting('Auth.views')['layout'] ?? 'CodeIgniter\Shield\Views\layout') ?>

<?= $this->section('main') ?>

<h1 class="h3 mb-3"><?= lang('PasskeyMfa.settingsHeading') ?></h1>

<?php if (session('message')) : ?>
    <div class="alert alert-success"><?= esc(session('message')) ?></div>
<?php endif ?>
<?php if (session('error')) : ?>
    <div class="alert alert-danger"><?= esc(session('error')) ?></div>
<?php endif ?>

<p class="text-muted"><?= lang('PasskeyMfa.settingsIntro') ?></p>

<?php if ($credentials === []) : ?>
    <p><?= lang('PasskeyMfa.noCredentials') ?></p>
<?php else : ?>
    <table class="table">
        <thead>
            <tr>
                <th><?= lang('PasskeyMfa.columnName') ?></th>
                <th><?= lang('PasskeyMfa.columnLastUsed') ?></th>
                <th><?= lang('PasskeyMfa.columnActions') ?></th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($credentials as $credential) : ?>
                <tr>
                    <td>
                        <form method="post" action="<?= url_to('passkey-settings-rename', $credential['id']) ?>" class="d-flex gap-2">
                            <?= csrf_field() ?>
                            <input
                                type="text"
                                name="name"
                                class="form-control form-control-sm"
                                value="<?= esc($credential['name'] ?? '') ?>"
                                placeholder="<?= lang('PasskeyMfa.unnamedCredential') ?>"
                            >
                            <button type="submit" class="btn btn-sm btn-outline-secondary">
                                <?= lang('PasskeyMfa.renameButton') ?>
                            </button>
                        </form>
                    </td>
                    <td><?= $credential['last_used_at'] ? esc($credential['last_used_at']) : '—' ?></td>
                    <td>
                        <form method="post" action="<?= url_to('passkey-settings-delete', $credential['id']) ?>" onsubmit="return confirm('<?= lang('PasskeyMfa.removeConfirm') ?>');">
                            <?= csrf_field() ?>
                            <button type="submit" class="btn btn-sm btn-outline-danger">
                                <?= lang('PasskeyMfa.removeButton') ?>
                            </button>
                        </form>
                    </td>
                </tr>
            <?php endforeach ?>
        </tbody>
    </table>
<?php endif ?>

<a href="<?= url_to('passkey-settings-enroll') ?>" class="btn btn-primary">
    <?= lang('PasskeyMfa.addButton') ?>
</a>

<?= $this->endSection() ?>
