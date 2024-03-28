-module(nxtfr_account_mnesia).
-author("christian@flodihn.se").

-include_lib("stdlib/include/qlc.hrl").
-define(ACCOUNTS_TABLE, accounts).
-define(ACCOUNTS_HISTORY_TABLE, accounts_history).

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

-record(account, {
    uid :: binary(),
    email :: binary(),
    map :: map()}).

-record(account_history, {
    uid :: binary(),
    map :: map()}).

init() ->
    mnesia:start(),
    mnesia:create_schema([node()]),
    mnesia:change_table_copy_type(schema, node(), disc_copies),
    case lists:member(?ACCOUNTS_TABLE, mnesia:system_info(tables)) of
        true ->
            pass;
        false ->
            mnesia:create_table(?ACCOUNTS_TABLE, [
                {record_name, account},
                {attributes, record_info(fields, account)},
                {index, [email]},
                {disc_only_copies, [node()]}])
    end,
    case lists:member(?ACCOUNTS_HISTORY_TABLE, mnesia:system_info(tables)) of
        true ->
            pass;
        false ->
            mnesia:create_table(?ACCOUNTS_HISTORY_TABLE, [
                {record_name, account_history},
                {attributes, record_info(fields, account_history)},
                {disc_only_copies, [node()]}])
    end,
    {ok, []}.

-spec stop(MnesiaState :: []) -> ok.
stop(_MnesiaState) ->
    ok.

-spec create(AccountMap :: map(), MnesiaState :: []) -> {ok, created} | {error, Reason :: any()}.
create(#{uid := Uid, email := Email} = AccountMap, _MnesiaState) ->
    Record = #account{uid = Uid, email = Email, map = AccountMap},
    case write(?ACCOUNTS_TABLE, Record) of
        {atomic, ok} ->
            {ok, created};
        {aborted, Reason} ->
            {error, Reason}
    end.

-spec update(Account :: map(), MnesiaState :: []) -> {ok, updated} | not_found.
update(#{uid := Uid} = Account, _MnesiaState) ->
    case read({?ACCOUNTS_TABLE, Uid}) of 
        {atomic, [#account{uid = Uid} = Record]} ->
            case write(?ACCOUNTS_TABLE, Record#account{map = Account}) of
                {atomic, ok} ->
                    {ok, updated};
                {aborted, Reason} ->
                    {error, Reason}
            end;
        {atomic, []} ->
            not_found
    end.

-spec read_by_uid(Uid :: binary(), MnesiaState :: []) -> {ok, Account :: map()} | not_found.
read_by_uid(Uid, _MnesiaState) ->
    case read({?ACCOUNTS_TABLE, Uid}) of 
        {atomic, [Account]} -> {ok, Account#account.map};
        {atomic, []} -> not_found
    end.

-spec read_by_email(Email :: binary, MnesiaState :: []) -> {ok, Account :: map()} | not_found.
read_by_email(Email, _MnesiaState) ->
    case mnesia:dirty_index_read(?ACCOUNTS_TABLE, Email, #account.email) of
        [] -> not_found;
        [Account] -> {ok, Account#account.map}
    end.

-spec delete(Email :: binary, MnesiaState :: []) -> {ok, deleted} | not_found.
delete(Uid, _MnesiaState) ->
    case delete({?ACCOUNTS_TABLE, Uid}) of 
        {atomic, ok} -> {ok, deleted};
        {aborted, Reason} -> {error, Reason}
    end.

-spec create_history(Uid :: binary, MnesiaState :: []) -> {ok, created} | {error, Reason :: any()}.
create_history(#{uid := Uid} = History, _MnesiaState) -> 
    Record = #account_history{uid = Uid, map = History},
    case write(?ACCOUNTS_HISTORY_TABLE, Record) of
        {atomic, ok} ->
            {ok, created};
        {aborted, Reason} ->
            {error, Reason}
    end.

-spec read_history(Uid :: binary, MnesiaState :: []) -> {ok, History :: map() | not_found}.
read_history(Uid, _MnesiaState) ->
    case read({?ACCOUNTS_HISTORY_TABLE, Uid}) of 
        {atomic, [History]} -> {ok, History#account_history.map};
        {atomic, []} -> not_found
    end.

-spec update_history(History :: map(), MnesiaState :: []) -> {ok, updated} | {error, Reason :: any()} | not_found.
update_history(#{uid := Uid} = History, _MnesiaState) ->
    case read({?ACCOUNTS_HISTORY_TABLE, Uid}) of 
        {atomic, [#account_history{uid = Uid} = Record]} ->
            case write(?ACCOUNTS_HISTORY_TABLE, Record#account_history{map = History}) of
                {atomic, ok} ->
                    {ok, updated};
                {aborted, Reason} ->
                    {error, Reason}
            end;
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