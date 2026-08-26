<?php

declare(strict_types=1);

namespace PasskeyMfa\Commands;

use CodeIgniter\CLI\BaseCommand;
use CodeIgniter\CLI\CLI;
use CodeIgniter\Publisher\Publisher;
use CodeIgniter\Shield\Models\UserIdentityModel;
use Throwable;

/**
 * php spark passkey-mfa:setup
 *
 * Publishes Config/PasskeyMfa.php and Language/en/PasskeyMfa.php into
 * the host app. Deliberately does NOT publish (copy) the migration -
 * CodeIgniter's migration locator already auto-discovers migrations
 * directly from every registered namespace, exactly how Shield's own
 * migrations get found. Copying it into the app as well - which an
 * earlier version of a similar command, in the shield-totp-mfa
 * package, did - created two migrations trying to create the same
 * table: harmless until anything migrates across all namespaces at
 * once, at which point it fails with either a PHP "class already
 * declared" fatal or a SQL "table already exists" error. See that
 * package's README for the full story; not repeated here.
 */
class Setup extends BaseCommand
{
    protected $group       = 'PasskeyMfa';
    protected $name        = 'passkey-mfa:setup';
    protected $description = 'Publishes passkey MFA config and language file into your app.';
    protected $usage       = 'passkey-mfa:setup [--force]';
    protected $options     = [
        '--force' => 'Overwrite files that were already published by a previous run.',
    ];

    public function run(array $params)
    {
        if (! class_exists(UserIdentityModel::class)) {
            CLI::error('CodeIgniter Shield does not appear to be installed.');
            CLI::write('Install it first: composer require codeigniter4/shield');

            return;
        }

        if (! interface_exists(\Webauthn\PublicKeyCredentialSourceRepository::class) && ! class_exists(\Webauthn\PublicKeyCredential::class)) {
            CLI::error('web-auth/webauthn-lib does not appear to be installed.');
            CLI::write('Install it first: composer require web-auth/webauthn-lib');

            return;
        }

        $namespaces = service('autoloader')->getNamespace('PasskeyMfa');

        if ($namespaces === []) {
            CLI::error('Could not resolve the "PasskeyMfa" namespace.');
            CLI::write('Make sure it is registered in composer.json or app/Config/Autoload.php.');

            return;
        }

        $force  = (bool) CLI::getOption('force');
        $source = rtrim($namespaces[0], '/\\');

        $publisher = new Publisher($source, APPPATH);

        try {
            $publisher->addPaths(['Config', 'Language'])->merge($force);
        } catch (Throwable $e) {
            CLI::error('Publishing failed: ' . $e->getMessage());
            $this->printPublisherErrors($publisher);

            return;
        }

        $published = $publisher->getPublished();

        if ($published === []) {
            CLI::write('Nothing to publish - files already exist. Re-run with --force to overwrite.', 'yellow');
        } else {
            foreach ($published as $file) {
                CLI::write('  Published: ' . str_replace(APPPATH, 'app/', $file), 'green');
            }
        }

        $this->printPublisherErrors($publisher);
        $this->printRemainingSteps();
    }

    private function printPublisherErrors(Publisher $publisher): void
    {
        foreach ($publisher->getErrors() as $file => $error) {
            CLI::error('  ' . $file . ': ' . $error->getMessage());
        }
    }

    private function printRemainingSteps(): void
    {
        CLI::newLine();
        CLI::write('A few manual steps left:', 'yellow');

        CLI::newLine();
        CLI::write('1) Set your app\'s real domain as $rpId in app/Config/PasskeyMfa.php');
        CLI::write('   (or via passkeyMfa.rpId in .env) - a mismatch here is the single most');
        CLI::write('   common reason a passkey ceremony fails outright. No scheme, no port.');

        CLI::newLine();
        CLI::write('2) Run the migration - auto-discovered from this package, nothing to');
        CLI::write('   copy first (same as Shield\'s own migrations):');
        CLI::write('   php spark migrate --all');
        CLI::write('   (or: php spark migrate -n PasskeyMfa)');

        CLI::newLine();
        CLI::write('3) Register the action(s) in app/Config/Auth.php:');
        CLI::write('   public array $actions = [');
        CLI::write("       'register' => \\PasskeyMfa\\Authentication\\Actions\\PasskeyActivator::class, // optional");
        CLI::write("       'login'    => \\PasskeyMfa\\Authentication\\Actions\\PasskeyMfa::class,");
        CLI::write('   ];');

        CLI::newLine();
        CLI::write('4) Add the routes from routes-snippet.php to app/Config/Routes.php.');

        CLI::newLine();
        CLI::write('5) Before relying on this in production: actually register and log in');
        CLI::write('   with a real browser and authenticator at least once. See this');
        CLI::write('   package\'s README - the WebAuthn integration is the one part of this');
        CLI::write('   package where "the code looks right" is meaningfully less reassuring');
        CLI::write('   than usual.');
    }
}
