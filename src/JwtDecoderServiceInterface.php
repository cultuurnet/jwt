<?php

namespace CultuurNet\UDB3\Jwt;

use Lcobucci\JWT\Token as Jwt;
use ValueObjects\String\String as StringLiteral;

interface JWTDecoderServiceInterface
{
    /**
     * @param StringLiteral $tokenString
     * @return Jwt
     */
    public function parse(StringLiteral $tokenString);

    /**
     * @param Jwt $jwt
     * @return bool
     */
    public function validateData(Jwt $jwt);

    /**
     * @param Jwt $jwt
     * @return bool
     */
    public function verifySignature(Jwt $jwt);
}
