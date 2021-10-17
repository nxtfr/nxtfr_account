-module(nxtfr_account_mnesia).
-author("christian@flodihn.se").

-include_lib("stdlib/include/qlc.hrl").
-include("nxtfr_account.hrl").

-define(ACCOUNTS_TABLE, accounts).

-export([
    init/0,
    save/2,
    load_by_email/2,
    load_by_uid/2,
    delete/2,
    logical_delete/2
    ]).

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

save(Account, _MnesiaState) ->
    case write(Account) of
        {atomic, ok} ->
            {ok, saved};
        {error, Reason} ->
            {error, Reason}
    end.

load_by_email(Email, _MnesiaState) ->
    case mnesia:dirty_index_read(?ACCOUNTS_TABLE, Email, #account.email) of
        [] -> not_found;
        [Account] -> {ok, Account}
    end.

load_by_uid(Uid, _MnesiaState) ->
    case read({?ACCOUNTS_TABLE, Uid}) of 
        {atomic, [Account]} -> {ok, Account};
        {atomic, []} -> not_found
    end.

delete(Uid, _MnesiaState) ->
    case delete({?ACCOUNTS_TABLE, Uid}) of 
        {atomic, ok} -> {ok, deleted};
        {aborted, Reason} -> {error, Reason}
    end.

logical_delete(Uid, MnesiaState) ->
    case read({?ACCOUNTS_TABLE, Uid}) of 
        {atomic, [Account]} ->
            DeletedAccount = Account#account{deleted = true},
            {ok, saved} = save(DeletedAccount, MnesiaState),
            {ok, deleted};
        {atomic, []} -> 
            not_found
    end.

write(Account) ->
    F = fun() ->
        mnesia:write(?ACCOUNTS_TABLE, Account, write)
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