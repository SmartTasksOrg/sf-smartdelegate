<?php
declare(strict_types=1);

namespace SmartDelegate;

/**
 * A JSON integer that does not fit in 64 bits. PHP would silently turn it
 * into a float; the reference (Python) keeps it as an exact integer, so this
 * port does too. Create only through Num::parse(), which returns a PHP int
 * whenever the value fits.
 */
final class BigInt implements \JsonSerializable
{
    /** Decimal digits with an optional leading '-', no leading zeros. */
    public function __construct(public readonly string $digits)
    {
    }

    public function __toString(): string
    {
        return $this->digits;
    }

    /** json_encode() has no exact form for this; the digits are given as a string. Json::encode() writes the number. */
    public function jsonSerialize(): string
    {
        return $this->digits;
    }
}
