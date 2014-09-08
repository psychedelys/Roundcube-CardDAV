<?php

/**
 * Cryptography functions for the CardDAV addressbook extension
 *
 * The functions in these class perform 3DES encryption using the mcrypt library.
 * They are copied from the Roundcube projects (class: rcube) with three major changes
 * 
 * a) Encryption is done using an arbitrary key passed to the constructor
 * b) mcrypt is strictly required (no own 3DES encryption as fallback)
 * c) iv is generated using mcrypt_create_iv (uses /dev/urandom by default so should
 *    no longer be slow)
 *
 * @author Nils Oliver Kröger <nokroeger@posteo.de>
 * @copyright Nils Oliver Kröger
 * @since 31.08.2014
 * @version 0.5.2
 * @license http://www.gnu.org/licenses/agpl.html GNU AGPL v3 or later
 *
 */
class carddav_crypto{

    /**
     * Encryption Key
     *
     * @var string
     */
    private $key;


    /**
     * mcrypt instance to re-use
     * @var mcrypt_module
     */
    private $mcrypt_handle;

    /**
     * Init crypto
     *
     * @param   string      $key      The key to be used
     * @return  void
     */
    public function __construct($key)
    {
        $this->key = $key;
        $this->mcrypt_handle = mcrypt_module_open(MCRYPT_TripleDES, "", MCRYPT_MODE_CBC, "");
    }

    public function __destruct(){
        mcrypt_module_close($this->mcrypt_handle);
    }

    /**
     * Encrypt using 3DES
     *
     * @param string $clear clear text input
     * @param boolean $base64 whether or not to base64_encode() the result before returning
     *
     * @return string encrypted text
     */
    public function encrypt($clear, $base64 = true)
    {
        if (!$clear) {
            return '';
        }

        /*-
         * Add a single canary byte to the end of the clear text, which
         * will help find out how much of padding will need to be removed
         * upon decryption; see http://php.net/mcrypt_generic#68082
         */
        $clear = pack("a*H2", $clear, "80");

        $iv = mcrypt_create_iv(mcrypt_enc_get_iv_size($this->mcrypt_handle));
        mcrypt_generic_init($this->mcrypt_handle, $this->key, $iv);
        $cipher = $iv . mcrypt_generic($this->mcrypt_handle, $clear);
        mcrypt_generic_deinit($this->mcrypt_handle);

        return $base64 ? base64_encode($cipher) : $cipher;
    }


    /**
     * Decrypt 3DES-encrypted string
     *
     * @param string $cipher encrypted text
     * @param boolean $base64 whether or not input is base64-encoded
     *
     * @return string decrypted text
     */
    public function decrypt($cipher, $key = 'des_key', $base64 = true)
    {
        if (!$cipher) {
            return '';
        }

        $cipher = $base64 ? base64_decode($cipher) : $cipher;

        $iv_size = mcrypt_enc_get_iv_size($this->mcrypt_handle);
        $iv = substr($cipher, 0, $iv_size);

        // session corruption? (#1485970)
        if (strlen($iv) < $iv_size) {
            return '';
        }

        $cipher = substr($cipher, $iv_size);
        mcrypt_generic_init($this->mcrypt_handle, $key, $iv);
        $clear = mdecrypt_generic($this->mcrypt_handle, $cipher);
        mcrypt_generic_deinit($this->mcrypt_handle);
        mcrypt_module_close($this->mcrypt_handle);


        /*-
         * Trim PHP's padding and the canary byte; see note in
         * rcube::encrypt() and http://php.net/mcrypt_generic#68082
         */
        $clear = substr(rtrim($clear, "\0"), 0, -1);

        return $clear;
    }
}
