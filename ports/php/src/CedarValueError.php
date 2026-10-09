<?php
declare(strict_types=1);

namespace SmartDelegate;

/** JSON that is not a Cedar value or not a well-formed entity (the reference raises ValueError). */
final class CedarValueError extends \Exception
{
}
