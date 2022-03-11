-module(nxtfr_account_riak).
-author("christian@flodihn.se").

-define(ACCOUNTS_TABLE, <<"accounts">>).
-include("nxtfr_account.hrl").
-record(riak_state, {riak_client_pid}).

-export([
    init/0,
    stop/1,
    save/2,
    load_by_email/2,
    load_by_uid/2,
    delete/2,
    logical_delete/2
    ]).

init() ->
    {ok, RiakOptions} = application:get_env(nxtfr_account, riak_options),
    Hostname = proplists:get_value(hostname, RiakOptions, "127.0.0.1"),
    Port = proplists:get_value(port, RiakOptions, 8087),
    {ok, Pid} = riakc_pb_socket:start(Hostname, Port),
    error_logger:info_report({?MODULE, riak_connection_successful, Hostname, Port}),
    {ok, #riak_state{riak_client_pid = Pid}}.

stop(#riak_state{riak_client_pid = Pid}) ->
    riakc_pb_socket:stop(Pid),
    error_logger:info_report("Database Stopped").
    
save(#account{uid=Uid, email=Email} = AccountData, #riak_state{riak_client_pid = Pid}) ->
    NewAccount = riakc_obj:new(?ACCOUNTS_TABLE, Uid, term_to_binary(AccountData)),
    AccountMetaData = riakc_obj:get_update_metadata(NewAccount),
    AccountMetaData2 = riakc_obj:set_secondary_index(AccountMetaData, [{{binary_index, "email"}, [Email]}]),
    NewAccountWithIndex = riakc_obj:update_metadata(NewAccount, AccountMetaData2),
    riakc_pb_socket:put(Pid, NewAccountWithIndex, [{w, 1}, {dw, 1}, return_body]),
    {ok, saved}.

load_by_uid(Uid, #riak_state{riak_client_pid = Pid}) ->
    FetchedObj = riakc_pb_socket:get(Pid, ?ACCOUNTS_TABLE, Uid),
    case FetchedObj of
        {error, notfound}->
            not_found;
        _ ->
            {_, Value} = FetchedObj,
            {ok, binary_to_term(riakc_obj:get_value(Value))}    
    end.

load_by_email(Email, #riak_state{riak_client_pid = Pid} = RiakState) ->
    FetchedObj = riakc_pb_socket:get_index(Pid, ?ACCOUNTS_TABLE, {binary_index, "email"}, Email),
    case FetchedObj of
        {error, notfound} ->
            not_found;
        {ok, {index_results_v1, [], _, _}} ->
            not_found;
        {ok, {index_results_v1, [Uid], _, _}} ->
            load_by_uid(Uid, RiakState)
    end.

delete(Uid, #riak_state{riak_client_pid = Pid}) ->
    riakc_pb_socket:delete(Pid, ?ACCOUNTS_TABLE, Uid),
    {ok, deleted}.

logical_delete(Uid, RiakState) ->
    case load_by_uid(Uid, RiakState) of
        {ok, Account} ->
            DeletedAccount = Account#account{deleted = true},
            {ok, saved} = save(DeletedAccount, RiakState),
            {ok, deleted};
        not_found ->
            not_found
    end.