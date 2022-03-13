-module(nxtfr_account).
-author("christian@flodihn.se").
-behaviour(gen_server).

-include("nxtfr_account.hrl").

%% External exports
-export([
    start_link/0,
    create/2,
    create/3,
    read/1,
    read/2,
    add_avatar/2,
    remove_avatar/2,
    add_friend/2,
    remove_friend/2,
    lookup/1,
    lookup/2,
    update_email/2,
    update_password/2,
    update_extra/2,
    validate/2,
    delete/1,
    delete/2,
    restore/1,
    get_history/1
    ]).

%% gen_server callbacks
-export([
    init/1, handle_call/3, handle_cast/2, handle_info/2, code_change/3, terminate/2
    ]).

%% server state
-record(state, {storage_module, crypto_module, storage_state, crypto_state}).

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

-spec add_avatar(EmailOrUid :: {email, Email :: binary} | {uid, Uid :: binary}, AvatarUid :: binary()) -> {ok, avatar_added} | {error, account_not_found}.
add_avatar(EmailOrUid, AvatarUid) ->
    gen_server:call(?MODULE, {add_avatar, EmailOrUid, AvatarUid}).

-spec remove_avatar(EmailOrUid :: {email, Email :: binary} | {uid, Uid :: binary}, AvatarUid :: binary()) -> {ok, avatar_removed} | {error, avatar_not_found} | {error, account_not_found}.
remove_avatar(EmailOrUid, AvatarUid) ->
    gen_server:call(?MODULE, {remove_avatar, EmailOrUid, AvatarUid}).

-spec add_friend(EmailOrUid :: {email, Email :: binary} | {uid, Uid :: binary}, FriendUid :: binary()) -> {ok, friend_added} | {error, account_not_found}.
add_friend(EmailOrUid, FriendUid) ->
    gen_server:call(?MODULE, {add_friend, EmailOrUid, FriendUid}).

-spec remove_friend(EmailOrUid :: {email, Email :: binary} | {uid, Uid :: binary}, FriendUid :: binary()) -> {ok, friend_removed} | {error, friend_not_found} | {error, account_not_found}.
remove_friend(EmailOrUid, FriendUid) ->
    gen_server:call(?MODULE, {remove_friend, EmailOrUid, FriendUid}).

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

-spec validate(EmailOrUid :: {email, Email :: binary} | {uid, Uid :: binary}, Password :: binary()) -> {ok, validation_success} | {error, validation_failure} | {error, not_found}.
validate(EmailOrUid, Password) ->
    gen_server:call(?MODULE, {validate, EmailOrUid, Password}).

-spec delete(EmailOrUid :: {email, Email :: binary} | {uid, Uid :: binary}) -> {ok, account_deleted} | {error, account_not_found}.
delete(EmailOrUid) ->
    gen_server:call(?MODULE, {delete, EmailOrUid}).

-spec delete(EmailOrUid :: {email, Email :: binary} | {uid, Uid :: binary}, logical_delete) -> {ok, account_deleted} | {error, account_not_found}.
delete(EmailOrUid, logical_delete) ->
    gen_server:call(?MODULE, {delete, EmailOrUid, logical_delete}).

-spec restore(EmailOrUid :: {email, Email :: binary} | {uid, Uid :: binary}) -> {ok, account_restored} | {error, account_not_found}.
restore(EmailOrUid) ->
    gen_server:call(?MODULE, {restore, EmailOrUid}).

-spec get_history(EmailOrUid :: {email, Email :: binary} | {uid, Uid :: binary}) -> {ok, account_restored} | {error, account_not_found}.
get_history(EmailOrUid) ->
    gen_server:call(?MODULE, {get_history, EmailOrUid}).

init([]) ->
    %% In case the supervisor trigger restarts because of lost db connection
    %% or similar. We want to avoid restarting too quickly.
    timer:sleep(500),

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
    Email = undefined,
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

handle_call({add_avatar, EmailOrUid, AvatarUid}, _From, #state{storage_module = StorageModule} = State) ->
    case get_account(EmailOrUid, State) of
        {ok, #{avatars := Avatars} = Account} ->
            case lists:member(AvatarUid, Avatars) of
                true -> 
                    {reply, {ok, avatar_added}, State};
                false -> 
                    UpdatedAccount = Account#{
                        avatars => [AvatarUid | Avatars],
                        updated_at => get_rfc3339_time()
                    },
                    {ok, saved} = StorageModule:save(UpdatedAccount, State#state.storage_state),
                    {reply, {ok, avatar_added}, State}
            end;
        not_found ->
            {reply, {error, account_not_found}, State}
    end;

handle_call({remove_avatar, EmailOrUid, AvatarUid}, _From, #state{storage_module = StorageModule} = State) ->
    case get_account(EmailOrUid, State) of
        {ok, #{avatars := Avatars} = Account} ->
            case lists:member(AvatarUid, Avatars) of
                true ->
                    UpdatedAccount = Account#{
                        avatars => lists:delete(AvatarUid, Avatars),
                        updated_at => get_rfc3339_time()
                    },
                    {ok, saved} = StorageModule:save(UpdatedAccount, State#state.storage_state),
                    {reply, {ok, avatar_removed}, State}; 
                false ->
                    {reply, {ok, avatar_not_found}, State}
            end;
        not_found ->
            {reply, {error, not_found}, State}
    end;

handle_call({add_friend, EmailOrUid, FriendUid}, _From, #state{storage_module = StorageModule} = State) ->
    case get_account(EmailOrUid, State) of
        {ok, #{friends := Friends} = Account} ->
            case lists:member(FriendUid, Friends) of
                true -> 
                    {reply, {ok, friend_added}, State};
                false -> 
                    UpdatedAccount = Account#{
                        friends => [FriendUid | Friends],
                        updated_at => get_rfc3339_time()
                    },
                    {ok, saved} = StorageModule:save(UpdatedAccount, State#state.storage_state),
                    {reply, {ok, friend_added}, State}
            end;
        not_found ->
            {reply, {error, account_not_found}, State}
    end;

handle_call({remove_friend, EmailOrUid, FriendUid}, _From, #state{storage_module = StorageModule} = State) ->
    case get_account(EmailOrUid, State) of
        {ok, #{friends := Friends} = Account} ->
            case lists:member(FriendUid, Friends) of
                true ->
                    UpdatedAccount = Account#{
                        friends => lists:delete(FriendUid, Friends),
                        updated_at => get_rfc3339_time()
                    },
                    {ok, saved} = StorageModule:save(UpdatedAccount, State#state.storage_state),
                    {reply, {ok, friend_removed}, State}; 
                false ->
                    {reply, {ok, friend_not_found}, State}
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
                {ok, Account} ->
                    UpdatedAccount = Account#{
                        email => NewEmail,
                        updated_at => get_rfc3339_time()
                    },
                    {ok, saved} = StorageModule:save(UpdatedAccount, State#state.storage_state),
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
            {ok, saved} = StorageModule:save(UpdatedAccount, State#state.storage_state),
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
            {ok, saved} = StorageModule:save(UpdatedAccount, State#state.storage_state),
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

handle_call({delete, EmailOrUid}, _From, #state{storage_module = StorageModule} = State) ->
    case get_account(EmailOrUid, State) of
        {ok, #{uid := Uid}} ->
            {ok, deleted} = StorageModule:delete(Uid, State#state.storage_state),
            {reply, {ok, account_deleted}, State};
        not_found ->
            {reply, {error, account_not_found}, State}
    end;

handle_call({delete, EmailOrUid, logical_delete}, _From, #state{storage_module = StorageModule} = State) ->
    case get_account(EmailOrUid, include_logically_deleted, State) of
        {ok, Account} ->
            UpdatedAccount = Account#{deleted => true}, 
            {ok, saved} = StorageModule:save(UpdatedAccount, State#state.storage_state),
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
            {ok, saved} = StorageModule:save(UpdatedAccount, State#state.storage_state),
            {reply, {ok, account_restored}, State};
        {ok, #{deleted := false}} ->
            {reply, {ok, account_not_deleted}, State};
        not_found ->
            {reply, {error, account_not_found}, State}
    end;

handle_call({get_history, EmailOrUid}, _From, State) ->
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

%% @doc Implementation taken from https://github.com/afiskon/erlang-uuid-v4/blob/master/src/uuid.erl
make_uid() ->
    <<A:32, B:16, C:16, D:16, E:48>> = crypto:strong_rand_bytes(16),
    Str = io_lib:format("~8.16.0b-~4.16.0b-4~3.16.0b-~4.16.0b-~12.16.0b", 
                        [A, B, C band 16#0fff, D band 16#3fff bor 16#8000, E]),
    list_to_binary(Str).

get_rfc3339_time() ->
    list_to_binary(calendar:system_time_to_rfc3339(os:system_time(second))).

create_account(Email, Password, Extra, #state{
        crypto_module = CryptoModule,
        crypto_state = CryptoState,
        storage_module = StorageModule,
        storage_state = StorageState} = State) ->
    {ok, PasswordHash} = CryptoModule:hash_password(Password, CryptoState),
    Uid = make_uid(),
    %% In practive the probability of an UID already existing is almost none.
    not_found = StorageModule:get_by_uid(Uid, StorageState),
    History = #{
        uid => Uid,
        actions => [
            #{event => created, time => get_rfc3339_time}
        ]},
    {ok, saved} = StorageModule:save_history(History, StorageState),
    Account = #{
        uid => Uid,
        email => Email,
        password_hash => PasswordHash,
        avatars => [],
        friends => [],
        extra => Extra,
        created_at => get_rfc3339_time()
    },
    {ok, saved} = StorageModule:save(Account, StorageState),
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
            case StorageModule:get_by_email(Email, StorageState) of
                {ok, Account} -> {ok, Account};
                not_found -> not_found
            end;
        {uid, Uid} ->
            case StorageModule:get_by_uid(Uid, StorageState) of
                {ok, Account} -> {ok, Account};
                not_found -> not_found
            end
    end.

get_history(EmailOrUid, #state{storage_module = StorageModule, storage_state = StorageState}) ->
    case EmailOrUid of
        {email, Email} ->
            case StorageModule:get_by_email(Email, StorageState) of
                {ok, #{uid := Uid}} ->
                    StorageModule:get_history(Uid);
                not_found ->
                    not_found
            end;
        {uid, Uid} ->
            StorageModule:get_history(Uid, StorageState)
    end.

email_exists(Email, #state{storage_module = StorageModule} = State) ->
    case StorageModule:get_by_email(Email, State#state.storage_state) of
        {ok, _Account} -> true;
        not_found -> false
    end.