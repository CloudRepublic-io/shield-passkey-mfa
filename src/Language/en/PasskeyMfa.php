<?php

declare(strict_types=1);

return [
    // Login verification
    'verifyHeading'      => 'Confirm it\'s you',
    'verifyIntro'         => 'Use your passkey to finish signing in.',
    'verifyButton'        => 'Continue with passkey',
    'verificationFailed'  => 'That didn\'t work. Please try again.',
    'successMessage'      => 'Signed in successfully.',

    // Registration-time activator
    'activatorHeading'   => 'Set up a passkey',
    'activatorIntro'      => 'Add a passkey so you can sign in with your fingerprint, face, or device PIN instead of a code.',
    'registerButton'      => 'Create passkey',
    'skipButton'          => 'Skip for now',
    'registrationFailed'  => 'That didn\'t work. Please try again.',
    'deviceNameLabel'     => 'Name this passkey (optional)',
    'deviceNamePlaceholder' => "e.g. \"Sarah's iPhone\"",

    // Standalone self-service settings
    'settingsHeading'    => 'Passkeys',
    'settingsIntro'       => 'Passkeys let you sign in with your fingerprint, face, or device PIN instead of a code.',
    'addButton'           => 'Add a passkey',
    'noCredentials'       => 'You have no passkeys yet.',
    'columnName'          => 'Passkey',
    'columnLastUsed'      => 'Last used',
    'columnActions'       => '',
    'unnamedCredential'   => 'Unnamed passkey',
    'renameButton'        => 'Rename',
    'removeButton'        => 'Remove',
    'removeConfirm'       => 'Remove this passkey? You will no longer be able to sign in with it.',
    'addedMessage'        => 'Passkey added.',
    'renamedMessage'      => 'Passkey renamed.',
    'removedMessage'      => 'Passkey removed.',
    'nameRequired'        => 'Please enter a name.',

    // Step-up auth for sensitive pages
    'stepUpHeading'         => 'Confirm it\'s you',
    'stepUpIntro'           => 'This action requires confirming your identity. Use your passkey to continue.',
    'stepUpNeedsEnrollment' => 'This action requires a passkey. Please set one up first.',
    'stepUpFailed'          => 'That didn\'t work. Please try again.',
];
