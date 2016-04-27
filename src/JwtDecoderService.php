<?php

namespace CultuurNet\UDB3\Jwt;

use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token as Jwt;
use Lcobucci\JWT\ValidationData;
use ValueObjects\String\String as StringLiteral;

class JwtDecoderDecoderService implements JWTDecoderServiceInterface
{
    /**
     * @var Parser
     */
    private $parser;

    /**
     * @var ValidationData
     */
    private $validationData;

    /**
     * @var Signer
     */
    private $signer;

    /**
     * @var Key
     */
    private $publicKey;

    /**
     * @param Parser $parser
     * @param ValidationData $validationData
     * @param Signer $signer
     * @param Key $publicKey
     */
    public function __construct(
        Parser $parser,
        ValidationData $validationData,
        Signer $signer,
        Key $publicKey
    ) {
        $this->parser = $parser;
        $this->validationData = $validationData;
        $this->signer = $signer;
        $this->publicKey = $publicKey;
    }

    /**
     * @param StringLiteral $tokenString
     * @return Jwt
     */
    public function parse(StringLiteral $tokenString)
    {
        return $this->parser->parse(
            $tokenString->toNative()
        );
    }

    /**
     * @param Jwt $jwt
     * @return bool
     */
    public function validateData(Jwt $jwt)
    {
        return $jwt->validate($this->validationData);
    }

    /**
     * @param Jwt $jwt
     * @return bool
     */
    public function verifySignature(Jwt $jwt)
    {
        return $jwt->verify(
            $this->signer,
            $this->publicKey
        );
    }
}
