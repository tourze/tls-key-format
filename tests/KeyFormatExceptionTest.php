<?php

declare(strict_types=1);

namespace Tourze\TLSKeyFormat\Tests;

use PHPUnit\Framework\TestCase;
use Tourze\TLSKeyFormat\Exception\KeyFormatException;

/**
 * KeyFormatException异常类测试
 */
class KeyFormatExceptionTest extends TestCase
{
    public function test_constructor_withMessage()
    {
        $message = '测试异常消息';
        $exception = new KeyFormatException($message);
        
        $this->assertInstanceOf(\Exception::class, $exception);
        $this->assertSame($message, $exception->getMessage());
    }
    
    public function test_constructor_withMessageAndCode()
    {
        $message = '测试异常消息';
        $code = 1001;
        $exception = new KeyFormatException($message, $code);
        
        $this->assertSame($message, $exception->getMessage());
        $this->assertSame($code, $exception->getCode());
    }
    
    public function test_constructor_withPreviousException()
    {
        $previous = new \RuntimeException('前置异常');
        $exception = new KeyFormatException('当前异常', 0, $previous);
        
        $this->assertSame($previous, $exception->getPrevious());
    }
} 