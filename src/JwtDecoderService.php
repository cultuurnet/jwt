<?php

namespace CultuurNet\UDB3\Jwt;

use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token as Jwt;
use Lcobucci\JWT\ValidationData;
use ValueObjects\String\String as StringLiteral;

class JwtDecoderService implements JwtDecoderServiceInterface
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
     * @var string[]
     */
    private $requiredClaims;

    /**
     * @param Parser $parser
     * @param ValidationData $validationData
     * @param Signer $signer
     * @param Key $publicKey
     * @param string[] $requiredClaims
     */
    public function __construct(
        Parser $parser,
        ValidationData $validationData,
        Signer $signer,
        Key $publicKey,
        array $requiredClaims = []
    ) {
        $this->parser = $parser;
        $this->validationData = $validationData;
        $this->signer = $signer;
        $this->publicKey = $publicKey;
        $this->requiredClaims = $requiredClaims;

        if (count($requiredClaims) !== count(array_filter($this->requiredClaims, 'is_string'))) {
            throw new \InvalidArgumentException(
                "All required claims should be strings."
            );
        }
    }

    /**
     * @param StringLiteral $tokenString
     * @return Jwt
     */
    public function parse(StringLiteral $tokenString)
    {
        try {
            return $this->parser->parse(
                $tokenString->toNative()
            );
        } catch (\InvalidArgumentException $e) {
            throw new JwtParserException($e);
        }
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
    public function validateRequiredClaims(Jwt $jwt)
    {
        foreach ($this->requiredClaims as $claim) {
            if (!$jwt->hasClaim($claim)) {
                return false;
            }
        }

        return true;
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
