<?php

declare(strict_types=1);

namespace CultuurNet\UDB3\Jwt;

use Lcobucci\JWT\Claim\Basic;
use Lcobucci\JWT\Token;
use PHPUnit\Framework\TestCase;

final class Udb3TokenTest extends TestCase
{
    /**
     * @test
     */
    public function it_returns_uid_claim_as_id_if_present(): void
    {
        $token = new Udb3Token(
            new Token(
                ['alg' => 'none'],
                [
                    'uid' => new Basic('uid', '6e3ef9b3-e37b-428e-af30-05f3a96dbbe4'),
                    'https://publiq.be/uitidv1id' => new Basic('https://publiq.be/uitidv1id', 'b55f041e-5c5e-4850-9fb8-8cf73d538c56'),
                    'sub' => new Basic('sub', 'auth0|ce6abd8f-b1e2-4bce-9dde-08af64438e87'),
                ]
            )
        );

        $this->assertEquals('6e3ef9b3-e37b-428e-af30-05f3a96dbbe4', $token->id());
    }

    /**
     * @test
     */
    public function it_returns_uitid_v1_claim_as_id_if_present(): void
    {
        $token = new Udb3Token(
            new Token(
                ['alg' => 'none'],
                [
                    'https://publiq.be/uitidv1id' => new Basic('https://publiq.be/uitidv1id', 'b55f041e-5c5e-4850-9fb8-8cf73d538c56'),
                    'sub' => new Basic('sub', 'auth0|ce6abd8f-b1e2-4bce-9dde-08af64438e87'),
                ]
            )
        );

        $this->assertEquals('b55f041e-5c5e-4850-9fb8-8cf73d538c56', $token->id());
    }

    /**
     * @test
     */
    public function it_returns_sub_claim_without_prefix_as_id(): void
    {
        $token = new Udb3Token(
            new Token(
                ['alg' => 'none'],
                [
                    'sub' => new Basic('sub', 'auth0|ce6abd8f-b1e2-4bce-9dde-08af64438e87'),
                ]
            )
        );

        $this->assertEquals('ce6abd8f-b1e2-4bce-9dde-08af64438e87', $token->id());
    }

    /**
     * @test
     */
    public function it_returns_sub_claim_without_prefix_as_id_but_keeps_everything_after_the_first_pipe(): void
    {
        $token = new Udb3Token(
            new Token(
                ['alg' => 'none'],
                [
                    'sub' => new Basic('sub', 'auth0|ce6abd8f-b1e2-4bce-9dde-08af64438e87|after_first_pipe'),
                ]
            )
        );

        $this->assertEquals('ce6abd8f-b1e2-4bce-9dde-08af64438e87|after_first_pipe', $token->id());
    }

    /**
     * @test
     */
    public function it_returns_email_claim_as_email(): void
    {
        $token = new Udb3Token(
            new Token(
                ['alg' => 'none'],
                [
                    'email' => new Basic('email', 'zvonimir@madewithlove.be'),
                ]
            )
        );

        $this->assertEquals('zvonimir@madewithlove.be', $token->email());
    }

    /**
     * @test
     */
    public function it_returns_nick_claim_as_nickname_if_present(): void
    {
        $token = new Udb3Token(
            new Token(
                ['alg' => 'none'],
                [
                    'nick' => new Basic('nick', 'zvoni'),
                    'nickname' => new Basic('nickname', 'zvonimir'),
                ]
            )
        );

        $this->assertEquals('zvoni', $token->userName());
    }

    /**
     * @test
     */
    public function it_returns_nickname_claim_as_nickname(): void
    {
        $token = new Udb3Token(
            new Token(
                ['alg' => 'none'],
                [
                    'nickname' => new Basic('nickname', 'zvonimir'),
                ]
            )
        );

        $this->assertEquals('zvonimir', $token->userName());
    }
}
