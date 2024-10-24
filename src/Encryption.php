<?php

namespace Tigress;

use phpseclib3\Crypt\RSA;

/**
 * Class Encryption (PHP version 8.3)
 *
 * @author       Rudy Mas <rudy.mas@rudymas.be>
 * @copyright    2024, Rudy Mas (http://rudymas.be/)
 * @license      https://opensource.org/licenses/GPL-3.0 GNU General Public License, version 3 (GPL-3.0)
 * @version      0.1.0
 * @lastmodified 2024-10-24
 * @package      Tigress
 */
class Encryption
{
    private string $key = '';
    private string $iv = '';
    private string $hash = '';

    /**
     * Get the version of the Encryption
     *
     * @return string
     */
    public static function version(): string
    {
        return '0.1.0';
    }

    /**
     * Create a private key
     *
     * @param int $bits
     * @param string $type
     * @param string $password
     * @return string
     */
    public function createPrivateKey(int $bits, string $type, string $password = ''): string
    {
        $key = RSA::createKey($bits);
        $privateKey = $key->toString($type, ['password' => $password]);
        print('Private key:<br>' . $privateKey);
        return $privateKey;
    }

    /**
     * Create a public key
     *
     * @param string $privateKey
     * @param string $password
     * @return string
     */
    public function createPublicKey(string $privateKey, string $password): string
    {
        $key = RSA::load($privateKey, $password);
        $publicKey = $key->getPublicKey();
        print('Public key:<br>' . $publicKey);
        return $publicKey;
    }
}