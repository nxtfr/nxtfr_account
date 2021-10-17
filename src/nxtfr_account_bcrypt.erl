-module(nxtfr_account_bcrypt).
-author("christian@flodihn.se").

-export([
    init/0,
    hash_password/2,
    validate_password/3
    ]).

init() ->
    application:start(crypto),
    application:start(poolboy),
    application:start(bcrypt),
    {ok, []}.

hash_password(Password, _CryptoState) ->
    {ok, Salt} = bcrypt:gen_salt(),
    bcrypt:hashpw(Password, Salt).

validate_password(Password, PasswordHash, _CryptoState) ->
    case bcrypt:hashpw(Password, PasswordHash) of
        {ok, PasswordHash} -> {ok, validation_success};
        {ok, _OtherPasswordHash} -> {error, validation_failure}
    end.

