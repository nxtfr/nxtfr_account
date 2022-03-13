-module(nxtfr_account_riak).
-author("christian@flodihn.se").

-define(ACCOUNTS_TABLE, <<"accounts">>).
-define(ACCOUNTS_HISTORY_TABLE, <<"accounts_history">>).

-include("nxtfr_account.hrl").

-record(riak_state, {riak_client_pid :: pid()}).

-type riak_state() :: #riak_state{}.

-export([
    init/0,
    stop/1,
    save/2,
    get_by_email/2,
    get_by_uid/2,
    delete/2,
    save_history/2,
    get_history/2]).

-spec init() -> {ok, RiakState :: riak_state()}.
init() ->
    {ok, RiakOptions} = application:get_env(nxtfr_account, riak_options),
    Hostname = proplists:get_value(hostname, RiakOptions, "127.0.0.1"),
    Port = proplists:get_value(port, RiakOptions, 8087),
    {ok, Pid} = riakc_pb_socket:start(Hostname, Port),
    {ok, #riak_state{riak_client_pid = Pid}}.

-spec stop(RiakState :: riak_state()) -> ok.
stop(#riak_state{riak_client_pid = Pid}) ->
    riakc_pb_socket:stop(Pid).

-spec save(Account :: account(), RiakState :: riak_state()) -> {ok, saved}.    
save(#account{uid = Uid, email = Email} = Account, #riak_state{riak_client_pid = Pid}) ->
    NewAccount = riakc_obj:new(?ACCOUNTS_TABLE, Uid, term_to_binary(Account)),
    AccountMetaData = riakc_obj:get_update_metadata(NewAccount),
    AccountMetaData2 = riakc_obj:set_secondary_index(AccountMetaData, [{{binary_index, "email"}, [Email]}]),
    NewAccountWithIndex = riakc_obj:update_metadata(NewAccount, AccountMetaData2),
    riakc_pb_socket:put(Pid, NewAccountWithIndex, [{w, 1}, {dw, 1}, return_body]),
    {ok, saved}.

%-spec load_by_uid(Uid :: binary, RiakState :: riak_state()) -> {ok, Account :: account()} | not_found.
get_by_uid(Uid, #riak_state{riak_client_pid = Pid}) ->
    case riakc_pb_socket:get(Pid, ?ACCOUNTS_TABLE, Uid) of
        {error, notfound}->
            not_found;
        {ok, Object} ->
            {ok, binary_to_term(riakc_obj:get_value(Object))}    
    end.

-spec get_by_email(Email :: binary, RiakState :: riak_state()) -> {ok, Account :: account()} | not_found.
get_by_email(Email, #riak_state{riak_client_pid = Pid} = RiakState) ->
    case riakc_pb_socket:get_index(Pid, ?ACCOUNTS_TABLE, {binary_index, "email"}, Email) of
        {error, notfound} ->
            not_found;
        {ok, {index_results_v1, [], _, _}} ->
            not_found;
        {ok, {index_results_v1, [Uid], _, _}} ->
            get_by_uid(Uid, RiakState)
    end.

-spec delete(Email :: binary, RiakState :: riak_state()) -> {ok, deleted} | not_found.
delete(Uid, #riak_state{riak_client_pid = Pid}) ->
    riakc_pb_socket:delete(Pid, ?ACCOUNTS_TABLE, Uid),
    {ok, deleted}.

save_history(#account_history{uid = Uid} = History, #riak_state{riak_client_pid = Pid}) -> 
    NewHistory = riakc_obj:new(?ACCOUNTS_HISTORY_TABLE, Uid, term_to_binary(History)),
    riakc_pb_socket:put(Pid, NewHistory, [{w, 1}, {dw, 1}, return_body]),
    {ok, saved}.

get_history(Uid, #riak_state{riak_client_pid = Pid}) ->
    case riakc_pb_socket:get(Pid, ?ACCOUNTS_HISTORY_TABLE, Uid) of
        {error, notfound} ->
            not_found;
        {ok, Object} ->
            {ok, binary_to_term(riakc_obj:get_value(Object))}
    end.