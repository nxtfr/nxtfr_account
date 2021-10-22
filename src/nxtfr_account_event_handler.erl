-module(nxtfr_account_event_handler).
-author("christian@flodihn.se").
-behaviour(gen_event).

-export([init/1, handle_event/2, handle_call/2, handle_info/2, code_change/3, terminate/2]).
 
init([]) ->
    {ok, []}.
 
handle_event({register, {email, Email}, {password, Password}, {extra, Extra}}, State) ->
    error_logger:info_report({"AccountSystem: Received register", Email}),
    nxtfr_account:create(Email, Password, Extra),
    {ok, State};

handle_event(Event, State) ->
    error_logger:info_report({?MODULE, unknown_event, Event}),
    {ok, State}.
 
handle_call(_, State) ->
    {ok, ok, State}.
 
handle_info(_, State) ->
    {ok, State}.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
 
terminate(_Reason, _State) ->
    ok.