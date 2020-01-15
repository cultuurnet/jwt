<?php

namespace CultuurNet\UDB3\Jwt;

use ValueObjects\StringLiteral\StringLiteral;

interface JwtDecoderServiceInterface
{
    public function parse(StringLiteral $tokenString) : Udb3TokenInterface;

    public function validateData(Udb3TokenInterface $jwt) : bool;

    public function validateRequiredClaims(Udb3TokenInterface $udb3Token) : bool;

    public function verifySignature(Udb3TokenInterface $udb3Token) : bool;
}
