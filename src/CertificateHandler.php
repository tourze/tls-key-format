<?php

declare(strict_types=1);

namespace Tourze\TLSKeyFormat;

use Tourze\TLSKeyFormat\Exception\KeyFormatException;

/**
 * 证书处理实现
 */
class CertificateHandler
{
    private PemDerFormat $pemDerFormat;

    /**
     * 构造函数
     */
    public function __construct()
    {
        $this->pemDerFormat = new PemDerFormat();
    }

    /**
     * 从PEM格式证书中提取信息
     *
     * @param string $pemCert PEM格式证书
     *
     * @return array<string, mixed> 证书信息
     *
     * @throws KeyFormatException 如果提取失败
     */
    public function parseCertificate(string $pemCert): array
    {
        if (!$this->pemDerFormat->isValidPem($pemCert)) {
            throw new KeyFormatException('无效的PEM格式证书');
        }

        // 提取证书DER数据
        $derData = $this->pemDerFormat->pemToDer($pemCert);

        // 使用OpenSSL解析证书
        $cert = openssl_x509_parse($pemCert);
        if (false === $cert) {
            throw new KeyFormatException('OpenSSL无法解析证书: ' . openssl_error_string());
        }

        return $cert;
    }

    /**
     * 验证证书有效期
     *
     * @param string $pemCert PEM格式证书
     *
     * @return bool 证书是否在有效期内
     *
     * @throws KeyFormatException 如果验证失败
     */
    public function verifyCertificateValidity(string $pemCert): bool
    {
        $cert = $this->parseCertificate($pemCert);

        $currentTime = time();
        $validFrom = $cert['validFrom_time_t'] ?? 0;
        $validTo = $cert['validTo_time_t'] ?? 0;

        return $currentTime >= $validFrom && $currentTime <= $validTo;
    }

    /**
     * 从证书中提取公钥
     *
     * @param string $pemCert PEM格式证书
     *
     * @return string PEM格式公钥
     *
     * @throws KeyFormatException 如果提取失败
     */
    public function extractPublicKey(string $pemCert): string
    {
        $certResource = @openssl_x509_read($pemCert);
        if (false === $certResource) {
            throw new KeyFormatException('OpenSSL无法读取证书: ' . openssl_error_string());
        }

        $publicKey = openssl_pkey_get_public($certResource);
        if (false === $publicKey) {
            throw new KeyFormatException('OpenSSL无法提取公钥: ' . openssl_error_string());
        }

        $keyDetails = openssl_pkey_get_details($publicKey);
        if (false === $keyDetails) {
            throw new KeyFormatException('OpenSSL无法获取公钥详情: ' . openssl_error_string());
        }

        return $keyDetails['key'];
    }

    /**
     * 验证证书链
     *
     * @param string        $pemCert    待验证的PEM格式证书
     * @param array<string> $chainCerts 证书链（PEM格式证书数组）
     * @param string|null   $caFile     CA证书文件路径，可选
     *
     * @return bool 验证是否通过
     *
     * @throws KeyFormatException 如果验证失败
     */
    public function verifyCertificateChain(string $pemCert, array $chainCerts, ?string $caFile = null): bool
    {
        // 创建临时文件存储证书链
        $chainFile = tempnam(sys_get_temp_dir(), 'cert_chain_');
        if (false === $chainFile) {
            throw new KeyFormatException('无法创建临时文件');
        }

        try {
            // 写入证书链
            file_put_contents($chainFile, implode("\n", $chainCerts));

            // 验证证书
            $certResource = @openssl_x509_read($pemCert);
            if (false === $certResource) {
                throw new KeyFormatException('OpenSSL无法读取证书: ' . openssl_error_string());
            }

            $result = openssl_x509_verify($certResource, $chainFile);

            if (1 === $result) {
                return true;
            }
            if (0 === $result) {
                return false;
            }
            throw new KeyFormatException('OpenSSL验证证书链失败: ' . openssl_error_string());
        } finally {
            // 清理临时文件
            if (file_exists($chainFile)) {
                unlink($chainFile);
            }
        }
    }
}
