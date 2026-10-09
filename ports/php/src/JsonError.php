<?php
declare(strict_types=1);

namespace SmartDelegate;

/** Text that is not JSON, or a value that has no JSON form. */
final class JsonError extends \RuntimeException
{
}
