%%%-------------------------------------------------------------------
%% @doc nxtfr_account top level supervisor.
%% @end
%%%-------------------------------------------------------------------

-module(nxtfr_account_sup).
-author("christian@flodihn.se").
-behaviour(supervisor).

-export([start_link/0]).

-export([init/1]).

-define(SERVER, ?MODULE).

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

init([]) ->
    SupFlags = #{strategy => one_for_all,
                 intensity => 10,
                 period => 1},
    NxtfrAccount = #{
        id => nxtfr_account,
        start => {nxtfr_account, start_link, []},
        type => worker},
    ChildSpecs = [NxtfrAccount],
    {ok, {SupFlags, ChildSpecs}}.