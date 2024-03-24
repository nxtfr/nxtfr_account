%%%-------------------------------------------------------------------
%% @doc nxtfr_account public API
%% @end
%%%-------------------------------------------------------------------

-module(nxtfr_account_app).
-author("christian@flodihn.se").
-behaviour(application).

-export([start/0, start/2, stop/1]).

start() ->
    application:start(nxtfr_account_app).

start(_StartType, _StartArgs) ->
    nxtfr_account_sup:start_link().

stop(_State) ->
    ok.

%% internal functions
