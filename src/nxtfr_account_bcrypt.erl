-module(nxtfr_account_bcrypt).
-author("christian@flodihn.se").

-export([
    init/0,
    hash_password/2,
    validate_password/3
    ]).

-spec init() -> {ok, []}.
init() ->
    application:start(crypto),
    application:start(poolboy),
    application:start(bcrypt),
    {ok, []}.

-spec hash_password(Password :: binary(), _CryptoState :: []) -> {ok, PasswordHash :: binary()} | {error, bcrypt_failed}.
hash_password(Password, _CryptoState) ->
    {ok, Salt} = bcrypt:gen_salt(),
    case bcrypt:hashpw(Password, Salt) of
        {ok, PasswordHash} -> {ok, PasswordHash};
        {error, "bcrypt failed"} -> {error, bcrypt_failed}
    end.

-spec validate_password(Password :: binary(), PasswordHash :: binary(), _CryptoState :: []) -> {ok, validation_sucess} | {error, validation_failure}.
validate_password(Password, PasswordHash, _CryptoState) ->
    case bcrypt:hashpw(Password, PasswordHash) of
        {ok, PasswordHash} -> {ok, validation_success};
        {ok, _OtherPasswordHash} -> {error, validation_failure}
    end.

