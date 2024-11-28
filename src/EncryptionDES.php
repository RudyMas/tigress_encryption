<?php

namespace Tigress;

use phpseclib3\Crypt\TripleDES;
use Random\RandomException;

/**
 * Class Encryption DES (PHP version 8.4)
 *
 * @author       Rudy Mas
 * @copyright    2024, Rudy Mas
 * @license      https://opensource.org/licenses/GPL-3.0 GNU General Public License, version 3 (GPL-3.0)
 * @version      2024.11.28.0
 * @package      Tigress
 */
class EncryptionDES extends Encryption
{
    /**
     * Create a DES key
     *
     * DES typically uses a 24-byte key (for Triple DES)
     *
     * @param int $bytes
     * @return string
     * @throws RandomException
     */
    public function createKey(int $bytes = 24): string
    {
        // DES (TripleDES) typically uses 24-byte keys
        return base64_encode(random_bytes($bytes));
    }

    /**
     * Encrypt data using DES
     *
     * @param string $data
     * @param string $encryptionMode
     * @return string
     * @throws RandomException
     */
    public function encrypt(string $data, string $encryptionMode = 'cbc'): string
    {
        $des = new TripleDES($encryptionMode);

        // Load the key outside this class through $des->setKey('...');
        $des->setKey(base64_decode($this->key));

        if ($encryptionMode !== 'ecb') {
            // Load the IV outside this class through $des->setIV('...');
            if (empty($this->iv)) $this->iv = random_bytes(8);  // DES uses 8-byte IVs
            $des->setIV($this->iv);
        }

        $encrypted = $des->encrypt($data);

        // Store the hash of the encrypted data
        $this->hash = sha1($encrypted);

        return base64_encode($encrypted);
    }

    /**
     * Decrypt data using DES
     *
     * @param string $data
     * @param string $encryptionMode
     * @return string
     */
    public function decrypt(string $data, string $encryptionMode = 'cbc'): string
    {
        $des = new TripleDES($encryptionMode);

        // Load the key outside this class through $des->setKey('...');
        $des->setKey(base64_decode($this->key));

        if ($encryptionMode !== 'ecb') {
            // Load the IV outside this class through $des->setIV('...');
            $des->setIV($this->iv);
        }

        return $des->decrypt(base64_decode($data));
    }
}