-module(nxtfr_account_riak).
-author("christian@flodihn.se").

-define(ACCOUNTS_TABLE, <<"accounts">>).
-define(ACCOUNTS_HISTORY_TABLE, <<"accounts_history">>).

-record(riak_state, {riak_client_pid :: pid()}).

-type riak_state() :: #riak_state{}.

-define(PUT_ARGS, [{w, 1}, {dw, 1}]).

-export([
    init/0,
    stop/1,
    create/2,
    update/2,
    read_by_email/2,
    read_by_uid/2,
    delete/2,
    create_history/2,
    update_history/2,
    read_history/2]).

-spec init() -> {ok, RiakState :: riak_state()}.
init() ->
    %% In case the supervisor trigger restarts because of lost db connection
    %% or similar. We want to avoid restarting too quickly.
    timer:sleep(500),
    {ok, RiakOptions} = application:get_env(nxtfr_account, riak_options),
    Hostname = proplists:get_value(hostname, RiakOptions, "127.0.0.1"),
    Port = proplists:get_value(port, RiakOptions, 8087),
    {ok, Pid} = riakc_pb_socket:start(Hostname, Port),
    {ok, #riak_state{riak_client_pid = Pid}}.

-spec stop(RiakState :: riak_state()) -> ok.
stop(#riak_state{riak_client_pid = Pid}) ->
    riakc_pb_socket:stop(Pid).

-spec create(Account :: map(), RiakState :: riak_state()) -> {ok, created}.    
create(#{uid := Uid, email := undefined} = Account, #riak_state{riak_client_pid = Pid}) ->
    AccountObject = riakc_obj:new(?ACCOUNTS_TABLE, Uid, term_to_binary(Account)),
    riakc_pb_socket:put(Pid, AccountObject, ?PUT_ARGS),
    {ok, created};

create(#{uid := Uid, email := Email} = Account, #riak_state{riak_client_pid = Pid}) ->
    AccountObject = riakc_obj:new(?ACCOUNTS_TABLE, Uid, term_to_binary(Account)),
    AccountObjectWithEmailIndex = set_metadata_email_index(AccountObject, Email),
    riakc_pb_socket:put(Pid, AccountObjectWithEmailIndex, ?PUT_ARGS),
    {ok, created}.

-spec update(Account :: map(), RiakState :: riak_state()) -> {ok, updated} | not_found.
update(#{uid := Uid, email := Email} = Account, #riak_state{riak_client_pid = Pid}) ->
    case riakc_pb_socket:get(Pid, ?ACCOUNTS_TABLE, Uid) of
        {error, notfound} ->
            not_found;
        {ok, AccountObject} ->
            ExistingAccount = binary_to_term(riakc_obj:get_value(AccountObject)),
            case has_same_email(Account, ExistingAccount) of
                true ->
                    UpdatedAccountObject = riakc_obj:update_value(AccountObject, term_to_binary(Account)),
                    ok = riakc_pb_socket:put(Pid, UpdatedAccountObject, ?PUT_ARGS),
                    {ok, updated};
                false ->
                    UpdatedAccountObject = riakc_obj:update_value(AccountObject, term_to_binary(Account)),
                    UpdatedAccountObjectWithEmailIndex = set_metadata_email_index(UpdatedAccountObject, Email),
                    error_logger:info_report({?MODULE, updated_secondary_index, Email}),
                    ok = riakc_pb_socket:put(Pid, UpdatedAccountObjectWithEmailIndex, ?PUT_ARGS),
                    {ok, updated}
            end
    end.

-spec read_by_uid(Uid :: binary(), RiakState :: riak_state()) -> {ok, Account :: map()} | not_found.
read_by_uid(Uid, #riak_state{riak_client_pid = Pid}) ->
    case riakc_pb_socket:get(Pid, ?ACCOUNTS_TABLE, Uid) of
        {error, notfound} ->
            not_found;
        {ok, AccountObject} ->
            {ok, binary_to_term(riakc_obj:get_value(AccountObject))}    
    end.

-spec read_by_email(Email :: binary, RiakState :: riak_state()) -> {ok, Account :: map()} | not_found.
read_by_email(Email, #riak_state{riak_client_pid = Pid} = RiakState) ->
    case riakc_pb_socket:get_index(Pid, ?ACCOUNTS_TABLE, {binary_index, "email"}, Email) of
        {error, notfound} ->
            not_found;
        {ok, {index_results_v1, [], _, _}} ->
            not_found;
        {ok, {index_results_v1, [Uid], _, _}} ->
            read_by_uid(Uid, RiakState)
    end.

-spec delete(Email :: binary, RiakState :: riak_state()) -> {ok, deleted} | not_found.
delete(Uid, #riak_state{riak_client_pid = Pid}) ->
    riakc_pb_socket:delete(Pid, ?ACCOUNTS_TABLE, Uid),
    {ok, deleted}.

-spec create_history(Uid :: binary, RiakState :: riak_state()) -> {ok, created}.
create_history(#{uid := Uid} = History, #riak_state{riak_client_pid = Pid}) -> 
    HistoryObject = riakc_obj:new(?ACCOUNTS_HISTORY_TABLE, Uid, term_to_binary(History)),
    riakc_pb_socket:put(Pid, HistoryObject, ?PUT_ARGS),
    {ok, created}.

-spec read_history(Uid :: binary, RiakState :: riak_state()) -> {ok, History :: map() | not_found}.
read_history(Uid, #riak_state{riak_client_pid = Pid}) ->
    case riakc_pb_socket:get(Pid, ?ACCOUNTS_HISTORY_TABLE, Uid) of
        {error, notfound} ->
            not_found;
        {ok, Object} ->
            {ok, binary_to_term(riakc_obj:get_value(Object))}
    end.

-spec update_history(History :: map(), RiakState :: riak_state()) -> {ok, updated} | not_found.
update_history(#{uid := Uid} = History, #riak_state{riak_client_pid = Pid}) ->
    case riakc_pb_socket:get(Pid, ?ACCOUNTS_HISTORY_TABLE, Uid) of
        {error, notfound} ->
            not_found;
        {ok, HistoryObject} ->
            UpdatedHistoryObject = riakc_obj:update_value(HistoryObject, term_to_binary(History)),
            ok = riakc_pb_socket:put(Pid, UpdatedHistoryObject, ?PUT_ARGS),
            {ok, updated}
    end.

set_metadata_email_index(AccountObject, Email) ->
    AccountObjectMetaData = riakc_obj:get_update_metadata(AccountObject),
    AccountObjectMetaData2 = riakc_obj:set_secondary_index(AccountObjectMetaData, [{{binary_index, "email"}, [Email]}]),
    riakc_obj:update_metadata(AccountObject, AccountObjectMetaData2).

has_same_email(#{email := Email1}, #{email := Email2}) ->
    Email1 == Email2.