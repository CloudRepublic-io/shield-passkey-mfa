<?php

declare(strict_types=1);

namespace PasskeyMfa\Models;

use CodeIgniter\Model;

/**
 * @property int         $id
 * @property int         $user_id
 * @property string      $credential_id
 * @property string      $public_key_credential_source
 * @property string|null $name
 * @property string|null $last_used_at
 */
class PasskeyCredentialModel extends Model
{
    protected $table         = 'auth_passkey_credentials';
    protected $primaryKey    = 'id';
    protected $returnType    = 'array';
    protected $useTimestamps = true;
    protected $allowedFields = [
        'user_id',
        'credential_id',
        'public_key_credential_source',
        'name',
        'last_used_at',
    ];

    /** @return array<int, array<string, mixed>> */
    public function forUser(int $userId): array
    {
        return $this->where('user_id', $userId)
            ->orderBy('created_at', 'DESC')
            ->findAll();
    }

    public function findByCredentialId(string $credentialId): ?array
    {
        return $this->where('credential_id', $credentialId)->first();
    }

    public function touch(int $id): void
    {
        $this->update($id, ['last_used_at' => date('Y-m-d H:i:s')]);
    }
}
