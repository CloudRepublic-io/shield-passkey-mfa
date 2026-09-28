<?php

declare(strict_types=1);

namespace PasskeyMfa\Database\Migrations;

use CodeIgniter\Database\Forge;
use CodeIgniter\Database\Migration;

/**
 * Auto-discovered directly from this package's own registered
 * namespace - CodeIgniter's migration locator scans every registered
 * namespace's Database/Migrations directory automatically, the same
 * way Shield's own migrations get found. Once this package's
 * `PasskeyMfa` namespace is registered (via Composer, or manually in
 * app/Config/Autoload.php for a drop-in install), `php spark migrate --all`
 * (or `-n PasskeyMfa`) picks this up with nothing further needed.
 *
 * Do NOT copy this file into app/Database/Migrations/ - see the
 * shield-totp-mfa package's README for exactly why that pattern (used
 * by an earlier version of these packages) causes real problems:
 * either a PHP "class already declared" fatal, or a SQL "table already
 * exists" error, the moment anything migrates across all namespaces at
 * once.
 *
 * Unlike TotpMfa's single secret-per-user, a user can register several
 * passkeys (phone, laptop, a hardware key as backup), so this is a
 * proper one-row-per-credential table, closer in shape to
 * shield-totp-mfa's auth_remembered_devices than to a single secret
 * column.
 */
class CreateAuthPasskeyCredentials extends Migration
{
    /**
     * Created alongside Shield's own tables: on Config\Auth::$DBGroup when
     * it's set, otherwise the default connection - as Shield's migration does.
     */
    public function __construct(?Forge $forge = null)
    {
        $group = config('Auth')->DBGroup;

        if ($group !== null) {
            $this->DBGroup = $group;
        }

        parent::__construct($forge);
    }

    public function up(): void
    {
        $this->forge->addField([
            'id' => [
                'type'           => 'BIGINT',
                'unsigned'       => true,
                'auto_increment' => true,
            ],
            'user_id' => [
                // Must exactly match Shield's own users.id column type
                // for the foreign key below to be valid - MySQL
                // requires identical type/width/signedness. Confirmed
                // against Shield's actual migration source: users.id
                // is INT(11) UNSIGNED, NOT BIGINT (a real bug in an
                // earlier package in this series, caught the hard way).
                'type'       => 'INT',
                'constraint' => 11,
                'unsigned'   => true,
            ],
            // Base64url-encoded credential ID, as returned by the
            // browser - used to look up which credential a login
            // attempt is claiming to be.
            'credential_id' => [
                'type'       => 'VARCHAR',
                'constraint' => 255,
            ],
            // The credential's public key material, COSE-encoded, as
            // produced by Webauthn\PublicKeyCredentialSource -
            // serialized (JSON) via this package's own
            // WebauthnFactory, not stored as raw binary.
            'public_key_credential_source' => [
                'type' => 'TEXT',
            ],
            // User-facing label - defaults to a guess from the
            // registration context (see PasskeyIdentityStore), editable
            // from the settings page.
            'name' => [
                'type'       => 'VARCHAR',
                'constraint' => 191,
                'null'       => true,
            ],
            'last_used_at' => [
                'type' => 'DATETIME',
                'null' => true,
            ],
            'created_at' => [
                'type' => 'DATETIME',
                'null' => true,
            ],
            'updated_at' => [
                'type' => 'DATETIME',
                'null' => true,
            ],
        ]);

        $this->forge->addKey('id', true);
        $this->forge->addKey('user_id'); // looked up on every login attempt and the settings page
        $this->forge->addUniqueKey('credential_id'); // looked up by ID during an authentication ceremony

        $this->forge->addForeignKey('user_id', 'users', 'id', 'CASCADE', 'CASCADE');

        $this->forge->createTable('auth_passkey_credentials', true);
    }

    public function down(): void
    {
        $this->forge->dropTable('auth_passkey_credentials', true);
    }
}
