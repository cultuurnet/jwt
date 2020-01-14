<?php declare(strict_types=1);

namespace CultuurNet\UDB3\Jwt;

use Lcobucci\JWT\Token as Jwt;
use ValueObjects\StringLiteral\StringLiteral;

/**
 * Class FallbackJwtDecoder
 * @package CultuurNet\UDB3\Jwt
 *
 * A wrapper class that enables backwards compatibility
 * with old Authorization tokens
 */
class FallbackJwtDecoder implements JwtDecoderServiceInterface
{

    /**
     * @var JwtDecoderServiceInterface
     */
    private $primary;

    /**
     * @var JwtDecoderServiceInterface
     */
    private $fallbackDecoder;

    public function __construct(
        JwtDecoderServiceInterface $jwtDecoderService,
        JwtDecoderServiceInterface $newDecoderService
    ) {
        $this->primary = $jwtDecoderService;
        $this->fallbackDecoder = $newDecoderService;
    }

    /**
     * @inheritDoc
     */
    public function parse(StringLiteral $tokenString)
    {
        try {
            return $this->primary->parse($tokenString);
        } catch (JwtParserException $e) {
            return $this->fallbackDecoder->parse($tokenString);
        }
    }

    /**
     * @inheritDoc
     */
    public function validateData(Jwt $jwt)
    {
        if ($this->primary->validateData($jwt)) {
            return true;
        }

        return $this->fallbackDecoder->validateData($jwt);
    }

    /**
     * @inheritDoc
     */
    public function validateRequiredClaims(Jwt $jwt)
    {
        if ($this->primary->validateRequiredClaims($jwt)) {
            return true;
        }

        return $this->fallbackDecoder->validateRequiredClaims($jwt);
    }

    /**
     * @inheritDoc
     */
    public function verifySignature(Jwt $jwt)
    {
        if ($this->primary->verifySignature($jwt)) {
            return true;
        }

        return $this->fallbackDecoder->verifySignature($jwt);
    }
}
