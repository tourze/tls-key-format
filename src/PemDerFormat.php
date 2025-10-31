<?php

declare(strict_types=1);

namespace Tourze\TLSKeyFormat;

use Tourze\TLSKeyFormat\Exception\KeyFormatException;

/**
 * PEM和DER格式处理实现
 */
class PemDerFormat implements KeyFormatInterface
{
    /**
     * PEM格式转DER格式
     *
     * @param string $pemData PEM格式数据
     *
     * @return string DER格式数据
     *
     * @throws KeyFormatException 如果转换失败
     */
    public function pemToDer(string $pemData): string
    {
        if (!$this->isValidPem($pemData)) {
            throw new KeyFormatException('无效的PEM格式数据');
        }

        // 提取PEM内容（移除头部、尾部和换行符）
        $pattern = '/^-----BEGIN ([A-Z ]+)-----\r?\n(.*)\r?\n-----END ([A-Z ]+)-----$/s';
        $matchResult = preg_match($pattern, $pemData, $matches);
        if (1 !== $matchResult) {
            throw new KeyFormatException('无法解析PEM格式数据');
        }

        if ($matches[1] !== $matches[3]) {
            throw new KeyFormatException('PEM头部和尾部标识不匹配');
        }

        // 移除PEM数据中的所有空白字符
        $base64Data = preg_replace('/\s+/', '', $matches[2]);
        if (null === $base64Data) {
            throw new KeyFormatException('处理PEM数据失败');
        }

        // 解码Base64数据得到DER格式
        $binaryData = base64_decode($base64Data, true);
        if (false === $binaryData) {
            throw new KeyFormatException('PEM数据Base64解码失败');
        }

        return $binaryData;
    }

    /**
     * DER格式转PEM格式
     *
     * @param string $derData DER格式数据
     * @param string $type    PEM类型标识（如CERTIFICATE, PRIVATE KEY, PUBLIC KEY等）
     *
     * @return string PEM格式数据
     *
     * @throws KeyFormatException 如果转换失败
     */
    public function derToPem(string $derData, string $type): string
    {
        if (!$this->isValidDer($derData)) {
            throw new KeyFormatException('无效的DER格式数据');
        }

        // 验证类型标识
        $typeMatchResult = preg_match('/^[A-Z ]+$/', $type);
        if (1 !== $typeMatchResult) {
            throw new KeyFormatException('无效的PEM类型标识');
        }

        // 对DER数据进行Base64编码
        $base64Data = base64_encode($derData);

        // 按64个字符一行分割
        $formattedBase64 = chunk_split($base64Data, 64, "\n");

        // 构建PEM格式
        $pem = "-----BEGIN {$type}-----\n";
        $pem .= $formattedBase64;
        $pem .= "-----END {$type}-----\n";

        return $pem;
    }

    /**
     * 从PEM文件中提取密钥或证书数据
     *
     * @param string $pemData PEM格式数据
     *
     * @return array{type: string, data: string} 提取的密钥或证书信息，包含'type'和'data'键
     *
     * @throws KeyFormatException 如果提取失败
     */
    public function extractFromPem(string $pemData): array
    {
        if (!$this->isValidPem($pemData)) {
            throw new KeyFormatException('无效的PEM格式数据');
        }

        // 提取PEM类型和内容
        $pattern = '/^-----BEGIN ([A-Z ]+)-----\r?\n/m';
        $matchResult = preg_match($pattern, $pemData, $matches);
        if (1 !== $matchResult) {
            throw new KeyFormatException('无法解析PEM格式数据');
        }

        $type = $matches[1];
        $derData = $this->pemToDer($pemData);

        return [
            'type' => $type,
            'data' => $derData,
        ];
    }

    /**
     * 验证PEM格式是否有效
     *
     * @param string $pemData PEM格式数据
     *
     * @return bool 是否有效
     */
    public function isValidPem(string $pemData): bool
    {
        // 验证PEM格式（开始标记、结束标记和中间的Base64编码内容）
        $pattern = '/^-----BEGIN ([A-Z ]+)-----\r?\n(.*)\r?\n-----END ([A-Z ]+)-----$/s';
        $matchResult = preg_match($pattern, $pemData, $matches);
        if (1 !== $matchResult) {
            return false;
        }

        // 验证头部和尾部标识是否匹配
        if ($matches[1] !== $matches[3]) {
            return false;
        }

        // 验证内容是否是有效的Base64
        $base64Data = preg_replace('/\s+/', '', $matches[2]);
        if (null === $base64Data) {
            return false;
        }

        return false !== base64_decode($base64Data, true);
    }

    /**
     * 验证DER格式是否有效
     *
     * @param string $derData DER格式数据
     *
     * @return bool 是否有效
     */
    public function isValidDer(string $derData): bool
    {
        // DER格式验证很复杂，这里只做基本检查
        // 实际应用中可能需要更复杂的ASN.1结构验证

        // 检查数据长度
        if (strlen($derData) < 2) {
            return false;
        }

        // 检查数据是否为二进制（非文本）
        // 这是一个基本检查，不是确定性的
        $isBinary = false;
        for ($i = 0; $i < min(32, strlen($derData)); ++$i) {
            $byte = ord($derData[$i]);
            if ($byte < 32 && 9 !== $byte && 10 !== $byte && 13 !== $byte) {
                $isBinary = true;
                break;
            }
        }

        return $isBinary;
    }
}
