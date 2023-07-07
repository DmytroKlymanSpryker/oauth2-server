<?php

namespace LeagueTests\Utils;

use League\OAuth2\Server\CryptKey;
use PHPUnit\Framework\TestCase;

class CryptKeyTest extends TestCase
{
    public function testNoFile()
    {
        $this->expectException(\LogicException::class);

        new CryptKey('undefined file');
    }

    public function testKeyOpenSSLAsymmetricKeyObject()
    {
        $publicKey = '-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoKQH6XtTUYPSIWPjtcA3I6VBF3F3TZMd9RImq0YG55qGIJvOOP0MeVib
D7MFtN4hv6ke3NyYaaUfRaxQ6mrDGzd
YOzdkqebjUzSNnwd8eQCRL2rvOsgUhf2yghLBlxq+9yfpzDV3KQ58JkCqvV1trBt/ISjPtgbK24V3v55z+cN558DMgyQmV
8pYrTFzktFVlJP20DR08HzIGimlWq/ixUfY4K
rznqapnKMw1u6SVVgGem67LC8HO9Mfx3KDseJaG7oUbSWq8vaTW2ewjEfs5JRt1OMUol7CHHtqVprcMizclqCO9Kh
Dmpussq19l0LbKbGkC73uK0Nm8RyfGhiWCQIDAQAB
-----END PUBLIC KEY-----';

        $openSSLAsymmetricKey = openssl_get_publickey($publicKey);
        $key = new CryptKey($openSSLAsymmetricKey);

        $this->assertEquals($openSSLAsymmetricKey, $key->getKeyContents());
    }

    public function testKeyCreation()
    {
        $keyFile = __DIR__ . '/../Stubs/public.key';
        $key = new CryptKey($keyFile, 'secret');

        $this->assertEquals('file://' . $keyFile, $key->getKeyPath());
        $this->assertEquals('secret', $key->getPassPhrase());
    }

    public function testKeyString()
    {
        $keyContent = \file_get_contents(__DIR__ . '/../Stubs/public.key');

        if (!\is_string($keyContent)) {
            $this->fail('The public key stub is not a string');
        }

        $key = new CryptKey($keyContent);

        $this->assertEquals(
            $keyContent,
            $key->getKeyContents()
        );

        $keyContent = \file_get_contents(__DIR__ . '/../Stubs/private.key.crlf');

        if (!\is_string($keyContent)) {
            $this->fail('The private key (crlf) stub is not a string');
        }

        $key = new CryptKey($keyContent);

        $this->assertEquals(
            $keyContent,
            $key->getKeyContents()
        );
    }

    public function testUnsupportedKeyType()
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Invalid key supplied');

        try {
            // Create the keypair
            $res = \openssl_pkey_new([
                'digest_alg' => 'sha512',
                'private_key_bits' => 2048,
                'private_key_type' => OPENSSL_KEYTYPE_DSA,
            ]);
            // Get private key
            \openssl_pkey_export($res, $keyContent, 'mystrongpassword');
            $path = self::generateKeyPath($keyContent);

            new CryptKey($keyContent, 'mystrongpassword');
        } finally {
            if (isset($path)) {
                @\unlink($path);
            }
        }
    }

    public function testECKeyType()
    {
        try {
            // Create the keypair
            $res = \openssl_pkey_new([
                'digest_alg' => 'sha512',
                'curve_name' => 'prime256v1',
                'private_key_type' => OPENSSL_KEYTYPE_EC,
            ]);
            // Get private key
            \openssl_pkey_export($res, $keyContent, 'mystrongpassword');

            $key = new CryptKey($keyContent, 'mystrongpassword');

            $this->assertEquals('', $key->getKeyPath());
            $this->assertEquals('mystrongpassword', $key->getPassPhrase());
        } catch (\Throwable $e) {
            $this->fail('The EC key was not created');
        } finally {
            if (isset($path)) {
                @\unlink($path);
            }
        }
    }

    public function testRSAKeyType()
    {
        try {
            // Create the keypair
            $res = \openssl_pkey_new([
                 'digest_alg' => 'sha512',
                 'private_key_bits' => 2048,
                 'private_key_type' => OPENSSL_KEYTYPE_RSA,
            ]);
            // Get private key
            \openssl_pkey_export($res, $keyContent, 'mystrongpassword');

            $key = new CryptKey($keyContent, 'mystrongpassword');

            $this->assertEquals('', $key->getKeyPath());
            $this->assertEquals('mystrongpassword', $key->getPassPhrase());
        } catch (\Throwable $e) {
            $this->fail('The RSA key was not created');
        } finally {
            if (isset($path)) {
                @\unlink($path);
            }
        }
    }

    /**
     * @param string $keyContent
     *
     * @return string
     */
    private static function generateKeyPath($keyContent)
    {
        return 'file://' . \sys_get_temp_dir() . '/' . \sha1($keyContent) . '.key';
    }
}
