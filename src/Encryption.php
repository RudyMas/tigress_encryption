<?php

namespace Tigress;

/**
 * Class Encryption (PHP version 8.5)
 *
 * @author       Rudy Mas <rudy.mas@rudymas.be>
 * @copyright    2024-2025, Rudy Mas (http://rudymas.be/)
 * @license      https://opensource.org/licenses/GPL-3.0 GNU General Public License, version 3 (GPL-3.0)
 * @version      2025.12.09.0
 * @package      Tigress
 */
class Encryption
{
    protected string $key = '';
    protected mixed $keyPassword = false;
    protected string $iv = '';
    protected string $hash = '';

    /**
     * Get the version of the Encryption
     *
     * @return string
     */
    public static function version(): string
    {
        return '2025.12.09';
    }

    /**
     * Set the key
     *
     * @param string $key
     * @param mixed|false $password
     * @return void
     */
    public function setKey(string $key, mixed $password = false): void
    {
        $this->key = $key;
        $this->keyPassword = $password;
    }

    /**
     * Get the key
     *
     * @return string
     */
    public function getKey(): string
    {
        return $this->key;
    }

    /**
     * Set the IV
     *
     * @param string $iv
     * @return void
     */
    public function setIv(string $iv): void
    {
        $this->iv = base64_decode($iv);
    }

    /**
     * Get the IV
     *
     * @return string
     */
    public function getIv(): string
    {
        return base64_encode($this->iv);
    }

    /**
     * Set the hash
     *
     * @param string $hash
     * @return void
     */
    public function setHash(string $hash): void
    {
        $this->hash = $hash;
    }

    /**
     * Get the hash
     *
     * @return string
     */
    public function getHash(): string
    {
        return $this->hash;
    }
}