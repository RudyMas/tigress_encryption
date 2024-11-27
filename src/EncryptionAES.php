<?php

namespace Tigress;

use AllowDynamicProperties;
use phpseclib3\Crypt\AES;
use Random\RandomException;

/**
 * Class Encryption AES (PHP version 8.4)
 *
 * @author       Rudy Mas <rudy.mas@rudymas.be>
 * @copyright    2024, Rudy Mas (http://rudymas.be/)
 * @license      https://opensource.org/licenses/GPL-3.0 GNU General Public License, version 3 (GPL-3.0)
 * @version      2024.11.27.0
 * @package      Tigress
 */
#[AllowDynamicProperties] class EncryptionAES extends Encryption
{
    /**
     * Create a private key
     *
     * You can use following byte sizes: 16, 24, 32
     * - 16 bytes = 128 bits
     * - 24 bytes = 192 bits
     * - 32 bytes = 256 bits
     *
     * @param int $bytes
     * @return string
     * @throws RandomException
     */
    public function createKey(int $bytes = 32): string
    {
        return base64_encode(random_bytes($bytes));
    }

    /**
     * Encrypt data
     *
     * @param string $data
     * @param string $encryptionMode
     * @return string
     * @throws RandomException
     */
    public function encrypt(string $data, string $encryptionMode = 'cbc'): string
    {
        $aes = new AES($encryptionMode);

        // Load the key outside this class through $aes->setKey('...');
        $aes->setKey(base64_decode($this->key));

        if ($encryptionMode !== 'ecb') {
            // Load the IV outside this class through $aes->setIV('...');
            if (empty($this->iv)) $this->iv = random_bytes(16);
            $aes->setIV($this->iv);
        }

        $encrypted = $aes->encrypt($data);

        // Store the hash of the file data
        $this->hash = sha1($encrypted);

        return base64_encode($encrypted);
    }

    /**
     * Decrypt data
     *
     * @param string $data
     * @param string $encryptionMode
     * @return string
     */
    public function decrypt(string $data, string $encryptionMode = 'cbc'): string
    {
        $aes = new AES($encryptionMode);

        // Load the key outside this class through $aes->setKey('...');
        $aes->setKey(base64_decode($this->key));

        if ($encryptionMode !== 'ecb') {
            // Load the IV outside this class through $aes->setIV('...');
            $aes->setIV($this->iv);
        }

        return $aes->decrypt(base64_decode($data));
    }
}