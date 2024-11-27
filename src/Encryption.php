<?php

namespace Tigress;

/**
 * Class Encryption (PHP version 8.4)
 *
 * @author       Rudy Mas <rudy.mas@rudymas.be>
 * @copyright    2024, Rudy Mas (http://rudymas.be/)
 * @license      https://opensource.org/licenses/GPL-3.0 GNU General Public License, version 3 (GPL-3.0)
 * @version      2024.11.27.0
 * @package      Tigress
 */
class Encryption
{
    /**
     * @var string
     */
    protected string $key = '' {
        get {
            return $this->key;
        }
        set {
            $this->key = $value;
        }
    }

    /**
     * @var mixed|bool
     */
    protected mixed $keyPassword = false {
        get {
            return $this->keyPassword;
        }
        set {
            $this->keyPassword = $value;
        }
    }

    /**
     * @var string
     */
    private string $iv = '' {
        get {
            return base64_encode($this->iv);
        }
        set {
            $this->iv = base64_decode($value);
        }
    }

    /**
     * @var string
     */
    private string $hash = '' {
        get {
            return $this->hash;
        }
        set {
            $this->hash = $value;
        }
    }

    /**
     * Get the version of the Encryption
     *
     * @return string
     */
    public static function version(): string
    {
        return '2024.11.27.0';
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
}