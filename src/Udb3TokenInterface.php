<?php declare(strict_types=1);

namespace CultuurNet\UDB3\Jwt;

use Lcobucci\JWT\Token;

interface Udb3TokenInterface
{
    public function userName(): string;

    public function email(): string;

    public function id(): string;

    public function jwtToken(): Token;
}
