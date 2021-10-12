%%%-------------------------------------------------------------------
%% @doc nxtfr_account public API
%% @end
%%%-------------------------------------------------------------------

-module(nxtfr_account_app).

-behaviour(application).

-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
    nxtfr_account_sup:start_link().

stop(_State) ->
    ok.

%% internal functions
