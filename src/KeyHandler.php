<?php

declare(strict_types=1);

namespace Tourze\TLSKeyFormat;

use Tourze\TLSKeyFormat\Exception\KeyFormatException;

/**
 * 密钥处理实现
 */
class KeyHandler
{
    /**
     * @var PemDerFormat
     */
    private PemDerFormat $pemDerFormat;

    /**
     * 构造函数
     */
    public function __construct()
    {
        $this->pemDerFormat = new PemDerFormat();
    }

    /**
     * 将RSA私钥转换为公钥
     *
     * @param string $privateKeyPem PEM格式的RSA私钥
     * @return string PEM格式的RSA公钥
     * @throws KeyFormatException 如果转换失败
     */
    public function privateKeyToPublicKey(string $privateKeyPem): string
    {
        $privateKey = openssl_pkey_get_private($privateKeyPem);
        if ($privateKey === false) {
            throw new KeyFormatException('无法加载私钥: ' . openssl_error_string());
        }

        $keyDetails = openssl_pkey_get_details($privateKey);
        if ($keyDetails === false || !isset($keyDetails['key'])) {
            throw new KeyFormatException('无法获取密钥详情: ' . openssl_error_string());
        }

        return $keyDetails['key'];
    }

    /**
     * 生成RSA密钥对
     *
     * @param int $bits 密钥长度，默认2048
     * @return array 包含private_key和public_key的数组
     * @throws KeyFormatException 如果生成失败
     */
    public function generateRsaKeyPair(int $bits = 2048): array
    {
        // 生成私钥配置
        $config = [
            'private_key_bits' => $bits,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ];

        // 生成私钥
        $res = openssl_pkey_new($config);
        if ($res === false) {
            throw new KeyFormatException('生成RSA密钥对失败: ' . openssl_error_string());
        }

        // 导出私钥
        openssl_pkey_export($res, $privateKey);
        if (empty($privateKey)) {
            throw new KeyFormatException('导出私钥失败: ' . openssl_error_string());
        }

        // 导出公钥
        $keyDetails = openssl_pkey_get_details($res);
        if ($keyDetails === false || !isset($keyDetails['key'])) {
            throw new KeyFormatException('导出公钥失败: ' . openssl_error_string());
        }

        $publicKey = $keyDetails['key'];

        return [
            'private_key' => $privateKey,
            'public_key' => $publicKey,
        ];
    }

    /**
     * 生成EC密钥对
     *
     * @param string $curve 曲线名称，默认 'prime256v1'
     * @return array 包含private_key和public_key的数组
     * @throws KeyFormatException 如果生成失败
     */
    public function generateEcKeyPair(string $curve = 'prime256v1'): array
    {
        // 生成私钥配置
        $config = [
            'curve_name' => $curve,
            'private_key_type' => OPENSSL_KEYTYPE_EC,
        ];

        // 生成私钥
        $res = openssl_pkey_new($config);
        if ($res === false) {
            throw new KeyFormatException('生成EC密钥对失败: ' . openssl_error_string());
        }

        // 导出私钥
        openssl_pkey_export($res, $privateKey);
        if (empty($privateKey)) {
            throw new KeyFormatException('导出EC私钥失败: ' . openssl_error_string());
        }

        // 导出公钥
        $keyDetails = openssl_pkey_get_details($res);
        if ($keyDetails === false || !isset($keyDetails['key'])) {
            throw new KeyFormatException('导出EC公钥失败: ' . openssl_error_string());
        }

        $publicKey = $keyDetails['key'];

        return [
            'private_key' => $privateKey,
            'public_key' => $publicKey,
        ];
    }

    /**
     * 加密私钥
     *
     * @param string $privateKeyPem 未加密的PEM格式私钥
     * @param string $passphrase 加密密码
     * @param string $cipher 加密算法，默认为aes-256-cbc
     * @return string 加密后的PEM格式私钥
     * @throws KeyFormatException 如果加密失败
     */
    public function encryptPrivateKey(string $privateKeyPem, string $passphrase, string $cipher = 'aes-256-cbc'): string
    {
        $privateKey = openssl_pkey_get_private($privateKeyPem);
        if ($privateKey === false) {
            throw new KeyFormatException('无法加载私钥: ' . openssl_error_string());
        }

        $encryptedKey = '';
        $result = openssl_pkey_export($privateKey, $encryptedKey, $passphrase, ['cipher' => $cipher]);
        if ($result === false) {
            throw new KeyFormatException('私钥加密失败: ' . openssl_error_string());
        }

        return $encryptedKey;
    }

    /**
     * 解密私钥
     *
     * @param string $encryptedKeyPem 加密的PEM格式私钥
     * @param string $passphrase 加密密码
     * @return string 解密后的PEM格式私钥
     * @throws KeyFormatException 如果解密失败
     */
    public function decryptPrivateKey(string $encryptedKeyPem, string $passphrase): string
    {
        $privateKey = openssl_pkey_get_private($encryptedKeyPem, $passphrase);
        if ($privateKey === false) {
            throw new KeyFormatException('私钥解密失败: ' . openssl_error_string());
        }

        $decryptedKey = '';
        $result = openssl_pkey_export($privateKey, $decryptedKey);
        if ($result === false) {
            throw new KeyFormatException('导出解密私钥失败: ' . openssl_error_string());
        }

        return $decryptedKey;
    }
}
