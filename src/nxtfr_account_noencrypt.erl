-module(nxtfr_account_noencrypt).
-author("christian@flodihn.se").

-export([
    init/0,
    hash_password/2,
    validate_password/3
    ]).

init() ->
    {ok, []}.

hash_password(Password, _CryptoState) ->
    {ok, Password}.

validate_password(Password, PasswordHash, _CryptoState) ->
    case Password == PasswordHash of
        true -> {ok, validation_success};
        false -> {error, validation_failure}
    end.

