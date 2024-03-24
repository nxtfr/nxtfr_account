-module(nxtfr_account_mnesia).
-author("christian@flodihn.se").

-include_lib("stdlib/include/qlc.hrl").
-define(ACCOUNTS_TABLE, accounts).
-define(ACCOUNTS_HISTORY_TABLE, accounts_history).

-export([
    init/0,
    save/2,
    get_by_email/2,
    get_by_uid/2,
    delete/2,
    logical_delete/2,
    save_history/2,
    get_history/2
    ]).

-record(account, {
    uid :: binary(),
    email :: binary(),
    map :: map(),
    deleted :: true | false}).

-record(account_history, {
    uid :: binary(),
    map :: map()}).

init() ->
    mnesia:create_schema([node()]),
    mnesia:start(),
    case lists:member(?ACCOUNTS_TABLE, mnesia:system_info(tables)) of
        true ->
            pass;
        false ->
            mnesia:create_table(?ACCOUNTS_TABLE, [
                {record_name, account},
                {attributes, record_info(fields, account)},
                {index, [email, deleted]},
                {disc_copies, [node()]}]),
            mnesia:start()
    end,
    {ok, []}.

-spec save(AccountMap :: map(), MnesiaState :: []) -> {ok, saved} | {error, Reason :: any()}.
save(#{uid := Uid, email := Email, deleted := Deleted} = AccountMap, _MnesiaState) ->
    Record = #account{uid = Uid, email = Email, map = AccountMap, deleted = Deleted},
    case write(?ACCOUNTS_TABLE, Record) of
        {atomic, ok} ->
            {ok, saved};
        {aborted, Reason} ->
            {error, Reason}
    end.

get_by_email(Email, _MnesiaState) ->
    case mnesia:dirty_index_read(?ACCOUNTS_TABLE, Email, #account.email) of
        [] -> not_found;
        [Account] -> {ok, Account#account.map}
    end.

get_by_uid(Uid, _MnesiaState) ->
    case read({?ACCOUNTS_TABLE, Uid}) of 
        {atomic, [Account]} -> {ok, Account#account.map};
        {atomic, []} -> not_found
    end.

delete(Uid, _MnesiaState) ->
    case delete({?ACCOUNTS_TABLE, Uid}) of 
        {atomic, ok} -> {ok, deleted};
        {aborted, Reason} -> {error, Reason}
    end.

logical_delete(Uid, MnesiaState) ->
    case read({?ACCOUNTS_TABLE, Uid}) of 
        {atomic, [#account{map = AccountMap}]} ->
            DeletedAccountMap = AccountMap#{deleted => true}, 
            {ok, saved} = save(DeletedAccountMap, MnesiaState),
            {ok, deleted};
        {atomic, []} -> 
            not_found
    end.

-spec save_history(HistoryMap :: map(), MnesiaState :: []) -> {ok, saved} | {error, Reason :: any()}.
save_history(#{uid := Uid} = HistoryMap, _MnesiaState) ->
    Record = #account_history{uid = Uid, map = HistoryMap},
    case write(?ACCOUNTS_HISTORY_TABLE, Record) of
        {atomic, ok} ->
            {ok, saved};
        {aborted, Reason} ->
            {error, Reason}
    end.

get_history(Uid, _MnesiaState) ->
    case read({?ACCOUNTS_HISTORY_TABLE, Uid}) of 
        {atomic, [History]} -> {ok, History#account_history.map};
        {atomic, []} -> not_found
    end.

write(Table, Record) ->
    F = fun() ->
        mnesia:write(Table, Record, write)
    end,
    mnesia:transaction(F).
    
read(Q) ->
    F = fun() ->
        mnesia:read(Q)
    end,
    mnesia:transaction(F).
    
delete(Q) ->
    F = fun() ->
        mnesia:delete(Q)
    end,
    mnesia:transaction(F).