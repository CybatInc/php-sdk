<?php

declare(strict_types=1);

namespace Cybat\Sdk\Tests;

use Cybat\Sdk\Redact;
use PHPUnit\Framework\TestCase;

final class RedactTest extends TestCase
{
    public function testLuhnValidAcceptsRealTestCardNumbers(): void
    {
        $this->assertTrue(Redact::luhnValid('4111111111111111'));
        $this->assertTrue(Redact::luhnValid('5500005555555559'));
        $this->assertTrue(Redact::luhnValid('378282246310005')); // 15-digit Amex
    }

    public function testLuhnValidRejectsNonLuhnAndOutOfRangeLengths(): void
    {
        $this->assertFalse(Redact::luhnValid('4111111111111112'));
        $this->assertFalse(Redact::luhnValid('123456789012')); // 12 digits
        $this->assertFalse(Redact::luhnValid('12345678901234567890')); // 20 digits
    }

    public function testMasksLocalPartKeepsDomain(): void
    {
        $this->assertSame('contact j***n@example.com now', Redact::maskString('contact john@example.com now'));
    }

    public function testHandlesShortLocalPartsAndUrlEncodedAt(): void
    {
        $this->assertSame('a***@x.io', Redact::maskString('a@x.io'));
        $this->assertSame('/u?e=j***e@corp.co.uk', Redact::maskString('/u?e=jane.doe%40corp.co.uk'));
    }

    public function testMasksLuhnValidCardNumbers(): void
    {
        $this->assertSame('card XXXX-XXXX-XXXX-1111 ok', Redact::maskString('card 4111 1111 1111 1111 ok'));
        $this->assertSame('XXXX-XXXX-XXXX-1111', Redact::maskString('4111-1111-1111-1111'));
        $this->assertSame('XXXX-XXXX-XXXX-1111', Redact::maskString('4111111111111111'));
    }

    public function testLeavesOrdinaryLongNumbersAlone(): void
    {
        $s = 'ts=1789753852675 id=1234567890123456';
        $this->assertSame($s, Redact::maskString($s));
    }

    public function testStripsJwtsAndBearerTokens(): void
    {
        $jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
        $this->assertSame('x [REDACTED jwt] y', Redact::maskString('x ' . $jwt . ' y'));
        $this->assertSame('Authorization: Bearer [REDACTED]', Redact::maskString('Authorization: Bearer abcdef1234567890'));
        $this->assertSame('bearer [REDACTED]', Redact::maskString('bearer abcdef1234567890'));
    }

    public function testStripsProviderKeys(): void
    {
        $this->assertStringContainsString('[REDACTED key]', Redact::maskString('AKIAIOSFODNN7EXAMPLE'));
        $this->assertStringContainsString('[REDACTED key]', Redact::maskString('AIzaSyD-LtD5cRX-85O2EzfgqXcnW43CfE3cr5w'));
    }

    public function testStripsPrivateKeyBlocks(): void
    {
        $this->assertSame(
            '[REDACTED private-key]',
            Redact::maskString("-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----")
        );
    }

    public function testReplacesValueWithContentFreeDescriptor(): void
    {
        $out = Redact::maskString("/login?user=bob&password=' OR '1'='1'--&next=/home");
        $this->assertStringNotContainsString('OR', $out);
        $this->assertStringContainsString('password=[REDACTED len=', $out);
        $this->assertStringContainsString('quote', $out);
        $this->assertStringContainsString('comment', $out);
        $this->assertStringContainsString('user=bob', $out);
        $this->assertStringContainsString('next=/home', $out);
    }

    public function testDoesNotTouchLookalikeNames(): void
    {
        $s = '/x?sort_key=asc&monkey=1';
        $this->assertSame($s, Redact::maskString($s));
    }

    public function testMasksPlainTokenParam(): void
    {
        $this->assertSame('/api?token=[REDACTED len=12]', Redact::maskString('/api?token=abc123secret'));
    }

    /** @dataProvider idempotenceProvider */
    public function testIdempotence(string $s): void
    {
        $once = Redact::maskString($s);
        $this->assertSame($once, Redact::maskString($once));
    }

    /** @return array<int, array<int, string>> */
    public static function idempotenceProvider(): array
    {
        return [
            ['contact john@example.com'],
            ['4111 1111 1111 1111'],
            ["/login?password=' OR 1=1--&e=a@b.co"],
            ['Bearer abcdef1234567890'],
            ['eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijk'],
        ];
    }

    public function testMaskValueMasksSensitiveKeysKeepsRest(): void
    {
        $v = json_decode('{"user_id":123,"password":"x\' OR 1=1--","note":"mail me at a.b@c.com"}', true);
        $out = Redact::maskValue($v);
        $this->assertSame(123, $out['user_id']);
        $this->assertStringStartsWith('[REDACTED len=', $out['password']);
        $this->assertStringContainsString('sus=', $out['password']);
        $this->assertSame('mail me at a***b@c.com', $out['note']);
    }

    public function testKeepsOnlyLast4DigitsOfCardFields(): void
    {
        $v = json_decode('{"credit_card":"4111 1111 1111 1234","cardNumber":4111111111111234}', true);
        $out = Redact::maskValue($v);
        $this->assertSame('XXXX-XXXX-XXXX-1234', $out['credit_card']);
        $this->assertSame('XXXX-XXXX-XXXX-1234', $out['cardNumber']);
    }

    public function testRecursesIntoNestedObjectsAndArrays(): void
    {
        $v = json_decode('{"a":{"b":[{"token":"abcdef"}]}}', true);
        $out = Redact::maskValue($v);
        $this->assertStringStartsWith('[REDACTED len=6', $out['a']['b'][0]['token']);
    }

    public function testBoundedDeepAndWideInputs(): void
    {
        $deep = ['v' => 'x'];
        for ($i = 0; $i < 50; $i++) {
            $deep = ['n' => $deep];
        }
        Redact::maskValue($deep); // must not throw / hang

        $wide = [];
        for ($i = 0; $i < 500; $i++) {
            $wide['k' . $i] = $i;
        }
        $out = Redact::maskValue($wide);
        $this->assertLessThanOrEqual(51, count($out));
    }

    public function testIdempotentOnObjects(): void
    {
        $v = json_decode('{"password":"hunter2","email":"a@b.co"}', true);
        $once = Redact::maskValue($v);
        $twice = Redact::maskValue($once);
        $this->assertSame(json_encode($once), json_encode($twice));
    }

    public function testCustomerSuppliedKeyNameIsRedactedInMaskValue(): void
    {
        $v = json_decode('{"account_number":"9988776655","note":"hi"}', true);
        $out = Redact::maskValue($v, 0, ['account_number']);
        $this->assertStringStartsWith('[REDACTED len=', $out['account_number']);
        $this->assertSame('hi', $out['note']);
    }

    public function testWithoutExtraSensitiveKeysTheSameFieldIsLeftAlone(): void
    {
        $v = json_decode('{"account_number":"9988776655"}', true);
        $out = Redact::maskValue($v);
        $this->assertSame('9988776655', $out['account_number']);
    }

    public function testExtraSensitiveKeysMatchCaseInsensitively(): void
    {
        $v = json_decode('{"Account_Number":"9988776655"}', true);
        $out = Redact::maskValue($v, 0, ['account_number']);
        $this->assertStringStartsWith('[REDACTED len=', $out['Account_Number']);
    }

    public function testExtraSensitiveKeysDoNotWidenToSubstringMatches(): void
    {
        // "id" is deliberately short -- must only catch an exact key named "id",
        // never swallow unrelated keys that merely contain "id" as a substring.
        $v = json_decode('{"id":"secret-ish","residential_address":"123 Main St"}', true);
        $out = Redact::maskValue($v, 0, ['id']);
        $this->assertStringStartsWith('[REDACTED len=', $out['id']);
        $this->assertSame('123 Main St', $out['residential_address']);
    }

    public function testExtraSensitiveKeysExtendRatherThanReplaceTheBuiltInList(): void
    {
        $v = json_decode('{"password":"hunter2","account_number":"9988776655"}', true);
        $out = Redact::maskValue($v, 0, ['account_number']);
        $this->assertStringStartsWith('[REDACTED len=', $out['password']);
        $this->assertStringStartsWith('[REDACTED len=', $out['account_number']);
    }

    public function testExtraSensitiveKeysApplyInMaskBodyForJsonText(): void
    {
        $out = Redact::maskBody('{"account_number":"9988776655","ok":1}', ['account_number']);
        $this->assertStringNotContainsString('9988776655', $out);
    }

    public function testExtraSensitiveKeysApplyInMaskStringJsonPairPass(): void
    {
        $out = Redact::maskString('{"account_number":"9988776655"}', ['account_number']);
        $this->assertStringNotContainsString('9988776655', $out);
    }

    public function testRedactedShapeNeverContainsOriginalCharacters(): void
    {
        $out = Redact::redactedShape('SuperSecret123');
        $this->assertStringNotContainsString('Super', $out);
        $this->assertStringNotContainsString('Secret', $out);
        $this->assertStringNotContainsString('123', $out);
        $this->assertSame('[REDACTED len=14]', $out);
    }

    public function testCapTextLeavesShortAloneCapsLong(): void
    {
        $this->assertSame('abc', Redact::capText('abc', 10));
        $out = Redact::capText(str_repeat('x', 5000), 100);
        $this->assertLessThanOrEqual(140, strlen($out));
        $this->assertStringContainsString('truncated', $out);
    }

    public function testSnippetAroundWindowsOnTrigger(): void
    {
        $text = str_repeat('A', 3000) . "' OR '1'='1' --" . str_repeat('B', 3000);
        $out = Redact::snippetAround($text, 500);
        $this->assertStringContainsString("' OR '1'='1'", $out);
        $this->assertLessThan(600, strlen($out));
    }

    public function testSnippetAroundFallsBackToHead(): void
    {
        $this->assertStringStartsWith('ZZZ', Redact::snippetAround(str_repeat('Z', 3000), 200));
    }

    public function testMasksSensitiveKeysInCompleteJson(): void
    {
        $out = Redact::maskString('{"user":"bob","password":"hunter2","n":5}');
        $this->assertStringNotContainsString('hunter2', $out);
        $this->assertStringContainsString('"user":"bob"', $out);
        $this->assertStringContainsString('"password":"[REDACTED len=7]"', $out);
    }

    public function testMasksTruncatedJson(): void
    {
        $out = Redact::maskString('{"password":"hunter2","note":"a long text that got trunc…[truncated 900 bytes]');
        $this->assertStringNotContainsString('hunter2', $out);
    }

    public function testKeepsAttackShapeOfSecretField(): void
    {
        $out = Redact::maskString('{"password":"\' OR \'1\'=\'1\'--"}');
        $this->assertStringNotContainsString('OR', $out);
        $this->assertStringContainsString('quote', $out);
    }

    public function testMasksNumericCardAndCvv(): void
    {
        $this->assertSame(
            '{"card_number":"XXXX-XXXX-XXXX-1234","cvv":"[REDACTED len=3]"}',
            Redact::maskString('{"card_number":4111111111111234,"cvv":123}')
        );
    }

    public function testLeavesNonSensitiveKeysAndIdempotent(): void
    {
        $once = Redact::maskString('{"name":"x","token":"abcdef","email":"a.b@c.com"}');
        $this->assertStringContainsString('"name":"x"', $once);
        $this->assertSame($once, Redact::maskString($once));
    }

    public function testHandlesEscapedQuotesWithoutLeakingRemainder(): void
    {
        $out = Redact::maskString('{"secret":"ab\"cd-tail-should-not-leak","x":1}');
        $this->assertStringNotContainsString('tail-should-not-leak', $out);
    }

    public function testHandlesVeryLargeHostileInput(): void
    {
        $hostile = str_repeat('a', 200_000) . ' password=hunter2';
        $out = Redact::maskString($hostile);
        $this->assertStringNotContainsString('hunter2', $out);
        $this->assertLessThan(70_000, strlen($out));
    }

    public function testMaskBodyMasksParsedJsonByKeyName(): void
    {
        $this->assertStringContainsString('[REDACTED', Redact::maskBody('{"password":"x","ok":1}'));
    }

    public function testMaskBodyMasksTruncatedJsonThatCannotBeParsed(): void
    {
        $out = Redact::maskBody('{"password":"hunter2","note":"cut off here…[truncated 5000 bytes]');
        $this->assertStringNotContainsString('hunter2', $out);
    }

    public function testMaskBodyMasksFormEncodedBodies(): void
    {
        $out = Redact::maskBody('user=bob&password=hunter2&next=/');
        $this->assertStringNotContainsString('hunter2', $out);
    }

    public function testMaskBodyMasksAlreadyParsedObjects(): void
    {
        $v = json_decode('{"token":"abcdef"}', true);
        $out = json_encode(Redact::maskBody($v));
        $this->assertStringNotContainsString('abcdef', $out);
    }
}
