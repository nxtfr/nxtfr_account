-module(nxtfr_account_riak).

-export([
    init/0,
    stop/1,
    save/2,
    load/2,
    lookup_email/2,
    delete/2
    ]).

-record(riak_state, {riak_client_pid}).

-include("nxtfr_account.hrl").

init() ->
    {ok, Pid} = riakc_pb_socket:start("127.0.0.1", 8087),
    {ok, #riak_state{riak_client_pid = Pid}}.

stop(#riak_state{riak_client_pid = Pid}) ->
    riakc_pb_socket:stop(Pid),
    error_logger:info_report("Database Stopped").
    
save(#account{uid=Uid, email=Email} = AccountData, RiakState) ->
    NewAccount = riakc_obj:new(<<"accounts">>, Uid, term_to_binary(AccountData)),
    AccountMetaData = riakc_obj:get_update_metadata(NewAccount),
    AccountMetaData2 = riakc_obj:set_secondary_index(
        AccountMetaData,
        [{{integer_index, "email"}, [Email]}]),
    NewAccountWithIndex = riakc_obj:update_metadata(NewAccount, AccountMetaData2),
    riakc_pb_socket:put(
        RiakState#riak_state.riak_client_pid,
        NewAccountWithIndex, 
        [{w, 1}, {dw, 1}, return_body]),
    {ok, saved}.

load(Uid, RiakState) ->
    FetchedObj = riakc_pb_socket:get(
        RiakState#riak_state.riak_client_pid, <<"accounts">>, Uid),
    read_value(FetchedObj).

lookup_email(Email, RiakState) ->
    FetchedObj = riakc_pb_socket:get(
        RiakState#riak_state.riak_client_pid, <<"accounts">>, Email),
    case FetchedObj of
        {error, notfound} -> not_found;
        _ -> {ok, read_value(FetchedObj)}
    end.

delete(Uid, RiakState) ->
    riakc_pb_socket:delete(
        RiakState#riak_state.riak_client_pid, <<"accounts">>, Uid),
    {ok, account_deleted}.

read_value(FetchedObj)->
    case FetchedObj of
        {error, notfound}->
            {error, not_found};
        _ ->
            {_, Value} = FetchedObj,
            binary_to_term(riakc_obj:get_value(Value))    
    end.