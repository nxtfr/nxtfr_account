-module(nxtfr_account).
-author("christian@flodihn.se").
-behaviour(gen_server).

%% External exports
-export([
    start_link/0,
    create/2,
    create/3,
    read/1,
    read/2,
    link_avatar/2,
    unlink_avatar/2,
    link_friend/2,
    unlink_friend/2,
    lookup/1,
    lookup/2,
    update_email/2,
    update_password/2,
    update_extra/2,
    validate/2,
    lock/1,
    unlock/1,
    delete/1,
    logical_delete/1,
    restore/1,
    add_history/3,
    read_history/1]).

%% gen_server callbacks
-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    code_change/3,
    terminate/2]).

%% server state
-record(state, {storage_module, crypto_module, storage_state, crypto_state}).

-type state() :: #state{
    storage_module :: atom,
    crypto_module :: atom(),
    storage_state :: any(),
    crypto_state :: any()}.

%% The default "source" when recording history events performed by the system.
-define(SYSTEM_EVENT_SOURCE, account_system).

-spec start_link() -> {ok, Pid :: pid()}.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

-spec create(Password :: binary, Extra :: any()) -> {ok, Uid :: binary()}.
create(Password, Extra) ->
    gen_server:call(?MODULE, {create, Password, Extra}).

-spec create(Email :: binary, Password :: binary, Extra :: any()) -> {ok, Uid :: binary() | {error, email_already_exists}}.
create(Email, Password, Extra) ->
    gen_server:call(?MODULE, {create, Email, Password, Extra}).

-spec read(EmailOrUid :: {email, Email :: binary} | {uid, Uid :: binary}) -> {ok, Account :: map() | {error, account_not_found}}.
read(EmailOrUid) ->
    gen_server:call(?MODULE, {read, EmailOrUid}).

-spec read(EmailOrUid :: {email, Email :: binary} | {uid, Uid :: binary}, include_logically_deleted) -> {ok, Account :: map() | {error, account_not_found}}.
read(EmailOrUid, include_logically_deleted) ->
    gen_server:call(?MODULE, {read, EmailOrUid, include_logically_deleted}).

-spec link_avatar(EmailOrUid :: {email, Email :: binary} | {uid, Uid :: binary}, AvatarUid :: binary()) -> {ok, avatar_added} | {error, account_not_found}.
link_avatar(EmailOrUid, AvatarUid) ->
    gen_server:call(?MODULE, {link_avatar, EmailOrUid, AvatarUid}).

-spec unlink_avatar(EmailOrUid :: {email, Email :: binary} | {uid, Uid :: binary}, AvatarUid :: binary()) -> {ok, avatar_removed} | {error, avatar_not_found} | {error, account_not_found}.
unlink_avatar(EmailOrUid, AvatarUid) ->
    gen_server:call(?MODULE, {unlink_avatar, EmailOrUid, AvatarUid}).

-spec link_friend(EmailOrUid :: {email, Email :: binary} | {uid, Uid :: binary}, FriendUid :: binary()) -> {ok, friend_added} | {error, account_not_found}.
link_friend(EmailOrUid, FriendUid) ->
    gen_server:call(?MODULE, {link_friend, EmailOrUid, FriendUid}).

-spec unlink_friend(EmailOrUid :: {email, Email :: binary} | {uid, Uid :: binary}, FriendUid :: binary()) -> {ok, friend_removed} | {error, friend_not_found} | {error, account_not_found}.
unlink_friend(EmailOrUid, FriendUid) ->
    gen_server:call(?MODULE, {unlink_friend, EmailOrUid, FriendUid}).

-spec lookup(EmailOrUid :: {email, Email :: binary} | {uid, Uid :: binary}) -> {ok, Uid :: binary() | {error, account_not_found}}.
lookup(EmailOrUid) ->
    gen_server:call(?MODULE, {lookup, EmailOrUid}).

-spec lookup(EmailOrUid :: {email, Email :: binary} | {uid, Uid :: binary}, include_logically_deleted) -> {ok, Uid :: binary() | {error, account_not_found}}.
lookup(EmailOrUid, include_logically_deleted) ->
    gen_server:call(?MODULE, {lookup, EmailOrUid, include_logically_deleted}).

-spec update_email(EmailOrUid :: {email, Email :: binary} | {uid, Uid :: binary}, NewEmail :: binary()) -> {ok, email_updated} | {error, account_not_found} | {error, email_already_exists}.
update_email(EmailOrUid, NewEmail) ->
    gen_server:call(?MODULE, {update_email, EmailOrUid, NewEmail}).

-spec update_password(EmailOrUid :: {email, Email :: binary} | {uid, Uid :: binary}, NewEmail :: atom()) -> {ok, password_updated} | {error, account_not_found}.
update_password(EmailOrUid, NewPassword) ->
    gen_server:call(?MODULE, {update_password, EmailOrUid, NewPassword}).

-spec update_extra(EmailOrUid :: {email, Email :: binary} | {uid, Uid :: binary}, Extra :: any()) -> {ok, extra_updated} | {error, account_not_found}.
update_extra(EmailOrUid, NewExtra) ->
    gen_server:call(?MODULE, {update_extra, EmailOrUid, NewExtra}).

-spec validate(EmailOrUid :: {email, Email :: binary} | {uid, Uid :: binary}, Password :: binary()) -> {ok, validation_success} | {error, validation_failure} | {error, account_not_found}.
validate(EmailOrUid, Password) ->
    gen_server:call(?MODULE, {validate, EmailOrUid, Password}).

-spec lock(EmailOrUid :: {email, Email :: binary} | {uid, Uid :: binary}) -> {ok, account_locked} | {error, account_already_locked} | {error, account_not_found}.
lock(EmailOrUid) ->
    gen_server:call(?MODULE, {lock, EmailOrUid}).

-spec unlock(EmailOrUid :: {email, Email :: binary} | {uid, Uid :: binary}) -> {ok, account_unlocked} | {error, account_not_locked} | {error, account_not_found}.
unlock(EmailOrUid) ->
    gen_server:call(?MODULE, {unlock, EmailOrUid}).

-spec delete(EmailOrUid :: {email, Email :: binary} | {uid, Uid :: binary}) -> {ok, account_deleted} | {error, account_not_found}.
delete(EmailOrUid) ->
    gen_server:call(?MODULE, {delete, EmailOrUid}).

-spec logical_delete(EmailOrUid :: {email, Email :: binary} | {uid, Uid :: binary}) -> {ok, account_deleted} | {error, account_not_found}.
logical_delete(EmailOrUid) ->
    gen_server:call(?MODULE, {logical_delete, EmailOrUid}).

-spec restore(EmailOrUid :: {email, Email :: binary} | {uid, Uid :: binary}) -> {ok, account_restored} | {error, account_not_found}.
restore(EmailOrUid) ->
    gen_server:call(?MODULE, {restore, EmailOrUid}).

-spec add_history(EmailOrUid :: {email, Email :: binary} | {uid, Uid :: binary}, Event :: atom(), Source :: any()) -> {ok, history_added} | {error, account_not_found}.
add_history(EmailOrUid, Event, Source) ->
    gen_server:call(?MODULE, {add_history, EmailOrUid, Event, Source}).

-spec read_history(EmailOrUid :: {email, Email :: binary} | {uid, Uid :: binary}) -> {ok, account_restored} | {error, account_not_found}.
read_history(EmailOrUid) ->
    gen_server:call(?MODULE, {read_history, EmailOrUid}).

-spec init([]) -> {ok, state()}.
init([]) ->
    application:start(nxtfr_event),
    nxtfr_event:add_global_handler(nxtfr_account, nxtfr_account_event_handler),
    {ok, StorageModule} = application:get_env(nxtfr_account, storage_module),
    {ok, CryptoModule} = application:get_env(nxtfr_account, crypto_module),
    {ok, AutoDiscoveryGroup} = application:get_env(nxtfr_account, autodiscovery_group),
    nxtfr_event:notify({join_autodiscovery_group, AutoDiscoveryGroup}),
    {ok, StorageState} = StorageModule:init(),
    {ok, CryptoState} = CryptoModule:init(),
    {ok, #state{
        storage_module = StorageModule,
        crypto_module = CryptoModule,
        storage_state = StorageState,
        crypto_state = CryptoState}}.

handle_call({create, Password, Extra}, _From, State) ->
    Email = <<"undefined">>,
    {ok, #{uid := Uid}} = create_account(Email, Password, Extra, State),
    {reply, {ok, Uid}, State};

handle_call({create, Email, Password, Extra}, _From, State) ->
    case email_exists(Email, State) of
        true -> 
            {reply, {error, email_already_exists}, State};
        false ->
            {ok, #{uid := Uid}} = create_account(Email, Password, Extra, State),
            {reply, {ok, Uid}, State}
    end;

handle_call({link_avatar, EmailOrUid, AvatarUid}, _From, #state{storage_module = StorageModule} = State) ->
    case get_account(EmailOrUid, State) of
        {ok, #{avatars := Avatars} = Account} ->
            case lists:member(AvatarUid, Avatars) of
                true -> 
                    {reply, {ok, avatar_linked}, State};
                false -> 
                    UpdatedAccount = Account#{
                        avatars => [AvatarUid | Avatars],
                        updated_at => get_rfc3339_time()
                    },
                    {ok, updated} = StorageModule:update(UpdatedAccount, State#state.storage_state),
                    {reply, {ok, avatar_linked}, State}
            end;
        not_found ->
            {reply, {error, account_not_found}, State}
    end;

handle_call({unlink_avatar, EmailOrUid, AvatarUid}, _From, #state{storage_module = StorageModule} = State) ->
    case get_account(EmailOrUid, State) of
        {ok, #{avatars := Avatars} = Account} ->
            case lists:member(AvatarUid, Avatars) of
                true ->
                    UpdatedAccount = Account#{
                        avatars => lists:delete(AvatarUid, Avatars),
                        updated_at => get_rfc3339_time()
                    },
                    {ok, updated} = StorageModule:update(UpdatedAccount, State#state.storage_state),
                    {reply, {ok, avatar_unlinked}, State}; 
                false ->
                    {reply, {ok, avatar_link_not_found}, State}
            end;
        not_found ->
            {reply, {error, not_found}, State}
    end;

handle_call({link_friend, EmailOrUid, FriendUid}, _From, #state{storage_module = StorageModule} = State) ->
    case get_account(EmailOrUid, State) of
        {ok, #{friends := Friends} = Account} ->
            case lists:member(FriendUid, Friends) of
                true -> 
                    {reply, {ok, friend_linked}, State};
                false -> 
                    UpdatedAccount = Account#{
                        friends => [FriendUid | Friends],
                        updated_at => get_rfc3339_time()
                    },
                    {ok, updated} = StorageModule:update(UpdatedAccount, State#state.storage_state),
                    {reply, {ok, friend_linked}, State}
            end;
        not_found ->
            {reply, {error, account_not_found}, State}
    end;

handle_call({unlink_friend, EmailOrUid, FriendUid}, _From, #state{storage_module = StorageModule} = State) ->
    case get_account(EmailOrUid, State) of
        {ok, #{friends := Friends} = Account} ->
            case lists:member(FriendUid, Friends) of
                true ->
                    UpdatedAccount = Account#{
                        friends => lists:delete(FriendUid, Friends),
                        updated_at => get_rfc3339_time()
                    },
                    {ok, updated} = StorageModule:update(UpdatedAccount, State#state.storage_state),
                    {reply, {ok, friend_unlinked}, State}; 
                false ->
                    {reply, {ok, friend_link_not_found}, State}
            end;
        not_found ->
            {reply, {error, not_found}, State}
    end;

handle_call({read, EmailOrUid}, _From, State) ->
    case get_account(EmailOrUid, State) of
        {ok, Account} ->
            {reply, {ok, Account}, State};
        not_found ->
            {reply, {error, account_not_found}, State}
    end;

handle_call({read, EmailOrUid, include_logically_deleted}, _From, State) ->
    case get_account(EmailOrUid, include_logically_deleted, State) of
        {ok, Account} ->
            {reply, {ok, Account}, State};
        not_found ->
            {reply, {error, account_not_found}, State}
    end;

handle_call({lookup, EmailOrUid}, _From, State) ->
    case get_account(EmailOrUid, State) of
        {ok, #{uid := Uid}} ->
            {reply, {ok, Uid}, State};
        not_found ->
            {reply, {error, account_not_found}, State}
    end;

handle_call({lookup, EmailOrUid, include_logically_deleted}, _From, State) ->
    case get_account(EmailOrUid, include_logically_deleted, State) of
        {ok, #{uid := Uid}} ->
            {reply, {ok, Uid}, State};
        not_found ->
            {reply, {error, account_not_found}, State}
    end;

handle_call({update_email, EmailOrUid, NewEmail}, _From, #state{storage_module = StorageModule} = State) ->
    case email_exists(NewEmail, State) of
        true ->
            {reply, {error, email_already_exists}, State};
        false ->
            case get_account(EmailOrUid, State) of
                {ok, #{email := OldEmail} = Account} ->
                    UpdatedAccount = Account#{
                        email => NewEmail,
                        updated_at => get_rfc3339_time()
                    },
                    {ok, history_added} = add_history(
                        EmailOrUid,
                        email_changed,
                        ?SYSTEM_EVENT_SOURCE,
                        <<"Email changed from ", OldEmail/binary, " to ", NewEmail/binary>>,
                        State),
                    {ok, updated} = StorageModule:update(UpdatedAccount, State#state.storage_state),
                    {reply, {ok, email_updated}, State};
                not_found ->
                    {reply, {error, account_not_found}, State}
            end
    end;

handle_call(
        {update_password, EmailOrUid, NewPassword},
        _From,
        #state{storage_module = StorageModule, crypto_module = CryptoModule} = State) ->
    case get_account(EmailOrUid, State) of
        {ok, Account} ->
            {ok, NewPasswordHash} = CryptoModule:hash_password(NewPassword, State#state.crypto_state),
            UpdatedAccount = Account#{
                password_hash => NewPasswordHash,
                updated_at => get_rfc3339_time()
            },
            {ok, history_added} = add_history(
                EmailOrUid,
                password_updated,
                ?SYSTEM_EVENT_SOURCE,
                State),
            {ok, updated} = StorageModule:update(UpdatedAccount, State#state.storage_state),
            {reply, {ok, password_updated}, State};
        not_found ->
            {reply, {error, account_not_found}, State}
    end;

handle_call({update_extra, EmailOrUid, NewExtra}, _From, #state{storage_module = StorageModule} = State) ->
    case get_account(EmailOrUid, State) of
        {ok, Account} ->
            UpdatedAccount = Account#{
                extra => NewExtra,
                updated_at => get_rfc3339_time()
            },
            {ok, updated} = StorageModule:update(UpdatedAccount, State#state.storage_state),
            {reply, {ok, extra_updated}, State};
        not_found ->
            {reply, {error, account_not_found}, State}
    end;

handle_call({validate, EmailOrUid, Password}, _From, #state{crypto_module = CryptoModule} = State) ->
    case get_account(EmailOrUid, State) of
        {ok, #{password_hash := PasswordHash}} ->
            %% ValidationResult returns {ok, validation_success} | error, validation_failure}
            ValidationResult = CryptoModule:validate_password(Password, PasswordHash, State#state.crypto_state),
            {reply, ValidationResult, State};
        not_found ->
            {reply, {error, account_not_found}, State}
    end;

handle_call({lock, EmailOrUid}, _From, #state{storage_module = StorageModule} = State) ->
    case get_account(EmailOrUid, State) of
        {ok, #{locked := false} = Account} ->
            UpdatedAccount = Account#{
                locked => true,
                updated_at => get_rfc3339_time()
            },
            {ok, history_added} = add_history(
                EmailOrUid,
                account_locked,
                ?SYSTEM_EVENT_SOURCE,
                State),
            {ok, updated} = StorageModule:update(UpdatedAccount, State#state.storage_state),
            {reply, {ok, account_locked}, State};
        {ok, #{locked := true}} ->
            {reply, {ok, account_already_locked}, State};
        not_found ->
            {reply, {error, account_not_found}, State}
    end;


handle_call({unlock, EmailOrUid}, _From, #state{storage_module = StorageModule} = State) ->
    case get_account(EmailOrUid, State) of
        {ok, #{locked := true} = Account} ->
            UpdatedAccount = Account#{
                locked => false,
                updated_at => get_rfc3339_time()
            },
            {ok, history_added} = add_history(
                EmailOrUid,
                account_unlocked,
                ?SYSTEM_EVENT_SOURCE,
                State),
            {ok, updated} = StorageModule:update(UpdatedAccount, State#state.storage_state),
            {reply, {ok, account_unlocked}, State};
        {ok, #{locked := false}} ->
            {reply, {error, account_not_locked}, State};
        not_found ->
            {reply, {error, account_not_found}, State}
    end;

handle_call({delete, EmailOrUid}, _From, #state{storage_module = StorageModule} = State) ->
    case get_account(EmailOrUid, State) of
        {ok, #{uid := Uid}} ->
            {ok, history_added} = add_history(
                EmailOrUid,
                account_permanently_deleted,
                ?SYSTEM_EVENT_SOURCE,
                State),
            {ok, deleted} = StorageModule:delete(Uid, State#state.storage_state),
            {reply, {ok, account_deleted}, State};
        not_found ->
            {reply, {error, account_not_found}, State}
    end;

handle_call({logical_delete, EmailOrUid}, _From, #state{storage_module = StorageModule} = State) ->
    case get_account(EmailOrUid, include_logically_deleted, State) of
        {ok, Account} ->
            UpdatedAccount = Account#{deleted => true}, 
            {ok, history_added} = add_history(
                EmailOrUid,
                account_logically_deleted,
                ?SYSTEM_EVENT_SOURCE,
                State),
            {ok, updated} = StorageModule:update(UpdatedAccount, State#state.storage_state),
            {reply, {ok, account_deleted}, State};
        not_found ->
            {reply, {error, account_not_found}, State}
    end;

handle_call({restore, EmailOrUid}, _From, #state{storage_module = StorageModule} = State) ->
    case get_account(EmailOrUid, include_logically_deleted, State) of
        {ok, #{deleted := true} = Account} ->
            UpdatedAccount = Account#{
                deleted => false,
                updated_at => get_rfc3339_time()
            },
            {ok, history_added} = add_history(
                EmailOrUid,
                account_restored,
                ?SYSTEM_EVENT_SOURCE,
                State),
            {ok, updated} = StorageModule:update(UpdatedAccount, State#state.storage_state),
            {reply, {ok, account_restored}, State};
        {ok, #{deleted := false}} ->
            {reply, {ok, account_not_deleted}, State};
        not_found ->
            {reply, {error, account_not_found}, State}
    end;

handle_call({add_history, EmailOrUid, Event, Source}, _From, State) ->
    case add_history(EmailOrUid, Event, Source, State) of
        {ok, history_added} ->
            {reply, {ok, history_added}, State};
        not_found ->
            {reply, {error, account_not_found}, State}
    end;

handle_call({read_history, EmailOrUid}, _From, State) ->
    case get_history(EmailOrUid, State) of
        {ok, History} ->
            {reply, {ok, History}, State};
        not_found ->
            {reply, {error, account_not_found}, State}
    end;

handle_call(Call, _From, State) ->
    error_logger:error_report([{undefined_call, Call}]),
    {reply, ok, State}.

handle_cast(Cast, State) ->
    error_logger:error_report([{undefined_cast, Cast}]),
    {noreply, State}.

handle_info(Info, State) ->
    error_logger:error_report([{undefined_info, Info}]),
    {noreply, State}.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

terminate(_Reason, _State) ->
    ok.

create_account(Email, Password, Extra, #state{
        crypto_module = CryptoModule,
        crypto_state = CryptoState,
        storage_module = StorageModule,
        storage_state = StorageState}) ->
    {ok, PasswordHash} = CryptoModule:hash_password(Password, CryptoState),
    Uid = make_uid(),
    %% In practive the probability of an UID already existing is almost zero.
    not_found = StorageModule:read_by_uid(Uid, StorageState),
    History = make_history(Uid),
    {ok, created} = StorageModule:create_history(History, StorageState),
    Account = make_account(Uid, Email, PasswordHash, Extra),
    {ok, created} = StorageModule:create(Account, StorageState),
    {ok, Account}.

get_account(EmailOrUid, State) ->
    case read_account_from_storage(EmailOrUid, State) of
        {ok, #{deleted := true}} -> not_found;
        {ok, Account} -> {ok, Account};
        not_found -> not_found
    end.

get_account(EmailOrUid, include_logically_deleted, State) ->
    case read_account_from_storage(EmailOrUid, State) of
        {ok, #{deleted := true} = Account} -> {ok, Account};
        {ok, Account} -> {ok, Account};
        not_found -> not_found
    end.

read_account_from_storage(EmailOrUid, #state{storage_module = StorageModule, storage_state = StorageState}) ->
    case EmailOrUid of
        {email, Email} ->
            case StorageModule:read_by_email(Email, StorageState) of
                {ok, Account} -> {ok, Account};
                not_found -> not_found
            end;
        {uid, Uid} ->
            case StorageModule:read_by_uid(Uid, StorageState) of
                {ok, Account} -> {ok, Account};
                not_found -> not_found
            end
    end.

add_history(EmailOrUid, Event, Source, State) ->
    add_history(EmailOrUid, Event, Source, <<>>, State).

add_history(EmailOrUid, Event, Source, Info, State) ->
    StorageModule = State#state.storage_module,
    StorageState = State#state.storage_state,
    HistoryEvent = make_history_event(Event, Source, Info),
    case get_history(EmailOrUid, State) of
        {ok, #{events := Events} = History} ->
            UpdatedHistory = History#{events => lists:append([HistoryEvent], Events)},
            {ok, updated} = StorageModule:update_history(UpdatedHistory, StorageState),
            {ok, history_added};
        not_found ->
            not_found
    end.

get_history(EmailOrUid, #state{storage_module = StorageModule, storage_state = StorageState}) ->
    case EmailOrUid of
        {email, Email} ->
            case StorageModule:read_by_email(Email, StorageState) of
                {ok, #{uid := Uid}} ->
                    StorageModule:read_history(Uid, StorageState);
                not_found ->
                    not_found
            end;
        {uid, Uid} ->
            StorageModule:read_history(Uid, StorageState)
    end.

email_exists(Email, #state{storage_module = StorageModule} = State) ->
    case StorageModule:read_by_email(Email, State#state.storage_state) of
        {ok, _Account} -> true;
        not_found -> false
    end.

%% @doc Implementation taken from https://github.com/afiskon/erlang-uuid-v4/blob/master/src/uuid.erl
make_uid() ->
    <<A:32, B:16, C:16, D:16, E:48>> = crypto:strong_rand_bytes(16),
    Str = io_lib:format("~8.16.0b-~4.16.0b-4~3.16.0b-~4.16.0b-~12.16.0b", 
                        [A, B, C band 16#0fff, D band 16#3fff bor 16#8000, E]),
    list_to_binary(Str).

make_account(Uid, Email, PasswordHash, Extra) ->
    #{
        uid => Uid,
        email => Email,
        password_hash => PasswordHash,
        avatars => [],
        friends => [],
        extra => Extra,
        locked => false,
        created_at => get_rfc3339_time()
    }.

make_history(Uid) ->
    #{
        uid => Uid,
        events => [make_history_event(account_created, system, <<>>)]
    }.

make_history_event(Event, Source, Info) ->
    #{
        event => Event,
        source => Source,
        info => Info,
        occured_at => get_rfc3339_time()
    }.

get_rfc3339_time() ->
    list_to_binary(calendar:system_time_to_rfc3339(os:system_time(second))).
