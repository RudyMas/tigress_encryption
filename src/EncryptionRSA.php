<?php

namespace Tigress;

use phpseclib3\Crypt\RSA;

/**
 * Class Encryption RSA (PHP version 8.3)
 *
 * @author       Rudy Mas <rudy.mas@rudymas.be>
 * @copyright    2024, Rudy Mas (http://rudymas.be/)
 * @license      https://opensource.org/licenses/GPL-3.0 GNU General Public License, version 3 (GPL-3.0)
 * @version      1.0.1
 * @lastmodified 2024-10-24
 * @package      Tigress
 */
class EncryptionRSA extends Encryption
{
    /**
     * Create a private key
     *
     * @param int $bits
     * @param string $type
     * @param string|false $password
     * @return string
     */
    public function createPrivateKey(int $bits, string $type = 'PKCS1', mixed $password = false): string
    {
        $key = RSA::createKey($bits);
        if (!empty($password)) {
            return $key->withPassword($password)->toString($type);
        }
        return $key->toString($type);
    }

    /**
     * Create a public key
     *
     * @param string $privateKey
     * @param string $type
     * @param string|false $password
     * @return string
     */
    public function createPublicKey(string $privateKey, string $type = 'PKCS1', mixed $password = false): string
    {
        $key = RSA::load($privateKey, $password);
        return $key->getPublicKey()->toString($type);
    }

    /**
     * Encrypt data
     *
     * @param string $data
     * @return string
     */
    public function encrypt(string $data): string
    {
        // Load the key outside this class through $rsa->setKey('...');
        $key = RSA::load($this->key, $this->keyPassword);
        return base64_encode($key->encrypt($data));
    }

    /**
     * Decrypt data
     *
     * @param string $data
     * @return string
     */
    public function decrypt(string $data): string
    {
        // Load the key outside this class through $rsa->setKey('...');
        $key = RSA::load($this->key, $this->keyPassword);
        return $key->decrypt(base64_decode($data));
    }
}