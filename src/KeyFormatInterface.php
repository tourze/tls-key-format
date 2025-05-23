<?php

declare(strict_types=1);

namespace Tourze\TLSKeyFormat;

use Tourze\TLSKeyFormat\Exception\KeyFormatException;

/**
 * 密钥格式处理接口
 *
 * 用于处理不同格式的密钥和证书，如PEM和DER格式
 */
interface KeyFormatInterface
{
    /**
     * PEM格式转DER格式
     *
     * @param string $pemData PEM格式数据
     * @return string DER格式数据
     * @throws KeyFormatException 如果转换失败
     */
    public function pemToDer(string $pemData): string;

    /**
     * DER格式转PEM格式
     *
     * @param string $derData DER格式数据
     * @param string $type PEM类型标识（如CERTIFICATE, PRIVATE KEY, PUBLIC KEY等）
     * @return string PEM格式数据
     * @throws KeyFormatException 如果转换失败
     */
    public function derToPem(string $derData, string $type): string;

    /**
     * 从PEM文件中提取密钥或证书数据
     *
     * @param string $pemData PEM格式数据
     * @return array 提取的密钥或证书信息
     * @throws KeyFormatException 如果提取失败
     */
    public function extractFromPem(string $pemData): array;

    /**
     * 验证PEM格式是否有效
     *
     * @param string $pemData PEM格式数据
     * @return bool 是否有效
     */
    public function isValidPem(string $pemData): bool;

    /**
     * 验证DER格式是否有效
     *
     * @param string $derData DER格式数据
     * @return bool 是否有效
     */
    public function isValidDer(string $derData): bool;
} 