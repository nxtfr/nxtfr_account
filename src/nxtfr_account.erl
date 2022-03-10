-module(nxtfr_account).
-author("christian@flodihn.se").
-behaviour(gen_server).

-include("nxtfr_account.hrl").

%% External exports
-export([
    start_link/0,
    create/2,
    create/3,
    read_by_email/1,
    read_by_uid/1,
    add_avatar_by_email/2,
    add_avatar_by_uid/2,
    lookup_by_email/1,
    lookup_by_uid/1,
    lookup_by_email/2,
    lookup_by_uid/2,
    update_email_by_email/2,
    update_email_by_uid/2,
    update_password_by_email/2,
    update_password_by_uid/2,
    update_extra_by_email/2,
    update_extra_by_uid/2,
    validate_by_email/2,
    validate_by_uid/2,
    delete_by_email/1,
    delete_by_uid/1,
    delete_by_email/2,
    delete_by_uid/2
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

-spec read_by_email(Email :: binary) -> {ok, Account :: map() | {error, not_found}}.
read_by_email(Email) ->
    gen_server:call(?MODULE, {read_by_email, Email}).

-spec read_by_uid(Uid :: binary) -> {ok, Account :: map() | {error, not_found}}.
read_by_uid(Uid) ->
    gen_server:call(?MODULE, {read_by_uid, Uid}).

-spec add_avatar_by_email(Email :: binary, AvatarUid :: binary()) -> {ok, added} | {error, not_found}.
add_avatar_by_email(Email, AvatarUid) ->
    gen_server:call(?MODULE, {add_avatar_by_email, Email, AvatarUid}).

-spec add_avatar_by_uid(Uid :: binary, AvatarUid :: binary()) -> {ok, added} | {error, not_found}.
add_avatar_by_uid(Uid, AvatarUid) ->
    gen_server:call(?MODULE, {add_avatar_by_uid, Uid, AvatarUid}).

-spec lookup_by_email(Email :: binary) -> {ok, Uid :: binary() | {error, not_found}}.
lookup_by_email(Email) ->
    gen_server:call(?MODULE, {lookup_by_email, Email}).

-spec lookup_by_uid(Uid :: binary) -> {ok, Uid :: binary() | {error, not_found}}.
lookup_by_uid(Uid) ->
    gen_server:call(?MODULE, {lookup_by_uid, Uid}).

-spec lookup_by_email(Email :: binary, include_logically_deleted) -> {ok, Uid :: binary() | {error, not_found}}.
lookup_by_email(Email, include_logically_deleted) ->
    gen_server:call(?MODULE, {lookup_by_email, Email, include_logically_deleted}).

-spec lookup_by_uid(Uid :: binary, include_logically_deleted) -> {ok, Uid :: binary() | {error, not_found}}.
lookup_by_uid(Uid, include_logically_deleted) ->
    gen_server:call(?MODULE, {lookup_by_uid, Uid, include_logically_deleted}).

-spec update_email_by_email(OldEmail :: binary, NewEmail :: atom()) -> {ok, Uid :: binary() | {error, not_found} | {error, email_already_exists}}.
update_email_by_email(OldEmail, NewEmail) ->
    gen_server:call(?MODULE, {update_email_by_email, OldEmail, NewEmail}).

-spec update_email_by_uid(Uid :: binary, NewEmail :: atom()) -> {ok, updated} | {error, not_found} | {error, email_already_exists}.
update_email_by_uid(Uid, NewEmail) ->
    gen_server:call(?MODULE, {update_email_by_uid, Uid, NewEmail}).

-spec update_password_by_email(Uid :: binary, NewEmail :: atom()) -> {ok, updated} | {error, not_found}.
update_password_by_email(Email, NewPassword) ->
    gen_server:call(?MODULE, {update_password_by_email, Email, NewPassword}).

-spec update_password_by_uid(Uid :: binary, NewPassword :: binary()) -> {ok, updated} | {error, not_found}.
update_password_by_uid(Uid, NewPassword) ->
    gen_server:call(?MODULE, {update_password_by_uid, Uid, NewPassword}).

-spec update_extra_by_email(Email :: binary, Extra :: any()) -> {ok, updated} | {error, not_found}.
update_extra_by_email(Email, NewExtra) ->
    gen_server:call(?MODULE, {update_extra_by_email, Email, NewExtra}).

-spec update_extra_by_uid(Uid :: binary, Extra :: any()) -> {ok, updated} | {error, not_found}.
update_extra_by_uid(Uid, NewExtra) ->
    gen_server:call(?MODULE, {update_extra_by_uid, Uid, NewExtra}).

-spec validate_by_email(Email :: binary, Password :: binary()) -> {ok, validation_success} | {error, validation_failure} | {error, not_found}.
validate_by_email(Email, Password) ->
    gen_server:call(?MODULE, {validate_by_email, Email, Password}).

-spec validate_by_uid(Uid :: binary, Password :: binary()) -> {ok, validation_success} | {error, validation_failure} | {error, not_found}.
validate_by_uid(Uid, Password) ->
    gen_server:call(?MODULE, {validate_by_uid, Uid, Password}).

-spec delete_by_email(Email :: binary) -> {ok, deleted} | {error, not_found}.
delete_by_email(Email) ->
    gen_server:call(?MODULE, {delete_by_email, Email}).

-spec delete_by_uid(Uid :: binary) -> {ok, deleted} | {error, not_found}.
delete_by_uid(Uid) ->
    gen_server:call(?MODULE, {delete_by_uid, Uid}).

-spec delete_by_email(Email :: binary, logical_delete) -> {ok, deleted} | {error, not_found}.
delete_by_email(Email, logical_delete) ->
    gen_server:call(?MODULE, {delete_by_email, Email, logical_delete}).

-spec delete_by_uid(Uid :: binary, logical_delete) -> {ok, deleted} | {error, not_found}.
delete_by_uid(Uid, logical_delete) ->
    gen_server:call(?MODULE, {delete_by_uid, Uid, logical_delete}).

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
    Email = undefined,
    {ok, Account} = create_account(Email, Password, Extra, State),
    {reply, {ok, Account#account.uid}, State};

handle_call({create, Email, Password, Extra}, _From, State) ->
    case get_account_by_email(Email, include_logically_deleted, State) of
        {ok, _ExistingAccount} -> 
            {reply, {error, email_already_exists}, State};
        not_found ->
            {ok, Account} = create_account(Email, Password, Extra, State),
            {reply, {ok, Account#account.uid}, State}
    end;

handle_call({add_avatar_by_email, Email, AvatarUid}, _From, #state{storage_module = StorageModule} = State) ->
    case get_account_by_email(Email, State) of
        {ok, #account{avatars = Avatars} = Account} ->
            UpdatedAccount = Account#account{avatars = [AvatarUid | Avatars]},
            {ok, saved} = StorageModule:save(UpdatedAccount, State#state.storage_state),
            {reply, {ok, added}, State};
        not_found ->
            {reply, {error, not_found}, State}
    end;

handle_call({add_avatar_by_uid, Uid, AvatarUid}, _From, #state{storage_module = StorageModule} = State) ->
    case get_account_by_uid(Uid, State) of
        {ok, #account{avatars = Avatars} = Account} ->
            UpdatedAccount = Account#account{avatars = [AvatarUid | Avatars]},
            {ok, saved} = StorageModule:save(UpdatedAccount, State#state.storage_state),
            {reply, {ok, added}, State};
        not_found ->
            {reply, {error, not_found}, State}
    end;


handle_call({read_by_email, Email}, _From, State) ->
    case get_account_by_email(Email, State) of
        {ok, Account} ->
            {reply, {ok, account_to_map(Account)}, State};
        not_found ->
            {reply, {error, not_found}, State}
    end;

handle_call({lookup_by_uid, Uid}, _From, State) ->
    case get_account_by_uid(Uid, State) of
        {ok, Account} ->
            {reply, {ok, account_to_map(Account)}, State};
        not_found ->
            {reply, {error, not_found}, State}
    end;


handle_call({lookup_by_email, Email}, _From, State) ->
    case get_account_by_email(Email, State) of
        {ok, Account} ->
            {reply, {ok, Account#account.uid}, State};
        not_found ->
            {reply, {error, not_found}, State}
    end;

handle_call({lookup_by_uid, Uid}, _From, State) ->
    case get_account_by_uid(Uid, State) of
        {ok, Account} ->
            {reply, {ok, Account#account.uid}, State};
        not_found ->
            {reply, {error, not_found}, State}
    end;

handle_call({lookup_by_email, Email, include_logically_deleted}, _From, State) ->
    case get_account_by_email(Email, include_logically_deleted, State) of
        {ok, Account} ->
            {reply, {ok, Account}, State};
        not_found ->
            {reply, {error, not_found}, State}
    end;

handle_call({lookup_by_uid, Uid, include_logically_deleted}, _From, State) ->
    case get_account_by_uid(Uid, State) of
        {ok, Account} ->
            {reply, {ok, Account#account.uid}, State};
        not_found ->
            {reply, {error, not_found}, State}
    end;

handle_call({update_email_by_email, OldEmail, NewEmail}, _From, #state{storage_module = StorageModule} = State) ->
    case email_exists(NewEmail, State) of
        true ->
            {reply, {error, email_already_exists}, State};
        false ->
            case get_account_by_email(OldEmail, State) of
                {ok, Account} ->
                    UpdatedAccount = Account#account{
                        email = NewEmail,
                        updated_at = get_rfc3339_time()},
                    {ok, saved} = StorageModule:save(UpdatedAccount, State#state.storage_state),
                    {reply, {ok, updated}, State};
                not_found ->
                    {reply, {error, not_found}, State}
            end
    end;

handle_call({update_email_by_uid, Uid, NewEmail}, _From, #state{storage_module = StorageModule} = State) ->
    case email_exists(NewEmail, State) of
        true ->
            {reply, {error, email_already_exists}, State};
        false ->
            case get_account_by_uid(Uid, State) of
                {ok, Account} ->
                    UpdatedAccount = Account#account{
                        email = NewEmail,
                        updated_at = get_rfc3339_time()},
                    {ok, saved} = StorageModule:save(UpdatedAccount, State#state.storage_state),
                    {reply, {ok, updated}, State};
                not_found ->
                    {reply, {error, not_found}, State}
            end
    end;

handle_call(
        {update_password_by_email, Email, NewPassword},
        _From,
        #state{storage_module = StorageModule, crypto_module = CryptoModule} = State) ->
    case get_account_by_email(Email, State) of
        {ok, Account} ->
            {ok, NewPasswordHash} = CryptoModule:hash_password(NewPassword, State#state.crypto_state),
            UpdatedAccount = Account#account{
                password_hash = NewPasswordHash,
                updated_at = get_rfc3339_time()},
            {ok, saved} = StorageModule:save(UpdatedAccount, State#state.storage_state),
            {reply, {ok, updated}, State};
        not_found ->
            {reply, {error, not_found}, State}
    end;

handle_call(
        {update_password_by_uid, Uid, NewPassword},
        _From,
        #state{storage_module = StorageModule, crypto_module = CryptoModule} = State) ->
    case get_account_by_uid(Uid, State) of
        {ok, Account} ->
            {ok, NewPasswordHash} = CryptoModule:hash_password(NewPassword, State#state.crypto_state),
            UpdatedAccount = Account#account{
                password_hash = NewPasswordHash,
                updated_at = get_rfc3339_time()},
            {ok, saved} = StorageModule:save(UpdatedAccount, State#state.storage_state),
            {reply, {ok, updated}, State};
        not_found ->
            {reply, {error, not_found}, State}
    end;

handle_call({update_extra_by_email, Email, NewExtra}, _From, #state{storage_module = StorageModule} = State) ->
    case get_account_by_email(Email, State) of
        {ok, Account} ->
            UpdatedAccount = Account#account{
                extra = NewExtra,
                updated_at = get_rfc3339_time()},
            {ok, saved} = StorageModule:save(UpdatedAccount, State#state.storage_state),
            {reply, {ok, updated}, State};
        not_found ->
            {reply, {error, not_found}, State}
    end;

handle_call({update_extra_by_uid, Uid, NewExtra}, _From, #state{storage_module = StorageModule} = State) ->
    case get_account_by_uid(Uid, State) of
        {ok, #account{deleted = false} = Account} ->
            UpdatedAccount = Account#account{
                extra = NewExtra,
                updated_at = get_rfc3339_time()},
            {ok, saved} = StorageModule:save(UpdatedAccount, State#state.storage_state),
            {reply, {ok, updated}, State};
        not_found ->
            {reply, {error, not_found}, State}
    end;

handle_call({validate_by_email, Email, Password}, _From, #state{crypto_module = CryptoModule} = State) ->
    case get_account_by_email(Email, State) of
        {ok, #account{password_hash = PasswordHash}} ->
            %% ValidationResult returns {ok, validation_success} | error, validation_failure}
            ValidationResult = CryptoModule:validate_password(Password, PasswordHash, State#state.crypto_state),
            {reply, ValidationResult, State};
        not_found ->
            {reply, {error, not_found}, State}
    end;

handle_call({validate_by_uid, Uid, Password}, _From, #state{crypto_module = CryptoModule} = State) ->
    case get_account_by_uid(Uid, State) of
        {ok, #account{password_hash = PasswordHash, deleted = false}} ->
            %% ValidationResult returns {ok, validation_success} | error, validation_failure}
            ValidationResult = CryptoModule:validate_password(Password, PasswordHash, State#state.crypto_state),
            {reply, ValidationResult, State};
        not_found ->
            {reply, {error, not_found}, State}
    end;

handle_call({delete_by_email, Email}, _From, #state{storage_module = StorageModule} = State) ->
    case get_account_by_email(Email, include_logically_deleted, State) of
        {ok, #account{uid = Uid}} ->
            DeleteResult = StorageModule:delete(Uid, State#state.storage_state),
            {reply, DeleteResult, State};
        not_found ->
            {reply, {error, not_found}, State}
    end;

handle_call({delete_by_email, Email, logical_delete}, _From, #state{storage_module = StorageModule} = State) ->
    case get_account_by_email(Email, include_logically_deleted, State) of
        {ok, #account{uid = Uid}} ->
            DeleteResult = StorageModule:logical_delete(Uid, State#state.storage_state),
            {reply, DeleteResult, State};
        not_found ->
            {reply, {error, not_found}, State}
    end;

handle_call({delete_by_uid, Uid}, _From, #state{storage_module = StorageModule} = State) ->
    case StorageModule:delete(Uid, State#state.storage_state) of
        {ok, deleted} ->
            {reply, {ok, deleted}, State};
        not_found ->
            {reply, {error, not_found}, State}
    end;

handle_call({delete_by_uid, Uid, logical_delete}, _From, #state{storage_module = StorageModule} = State) ->
    case StorageModule:logical_delete(Uid, State#state.storage_state) of
        {ok, deleted} ->
            {reply, {ok, deleted}, State};
        not_found ->
            {reply, {error, not_found}, State}
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

create_account(Email, Password, Extra, #state{crypto_module = CryptoModule, storage_module = StorageModule} = State) ->
    {ok, PasswordHash} = CryptoModule:hash_password(Password, State#state.crypto_state),
    Account = #account{
        uid = make_uid(),
        email = Email,
        password_hash = PasswordHash,
        avatars = [],
        extra = Extra,
        created_at = get_rfc3339_time()
    },
    {ok, saved} = StorageModule:save(Account, State#state.storage_state),
    {ok, Account}.

get_account(EmailOrUid, State) ->
    case read_account_from_storage(EmailOrUid, State) of
        {ok, #account{deleted = true}} -> not_found;
        {ok, Account} -> {ok, Account};
        not_found -> not_found
    end.

get_account(EmailOrUid, include_logically_deleted, State}) ->
    case read_account_from_storage(EmailOrUid, State) of
        {ok, #account{deleted = true}} -> {ok, Account};
        {ok, Account} -> {ok, Account};
        not_found -> not_found
    end.

read_account_from_storage(EmailOrUid, #state{storage_module = StorageModule, storage_state = StorageState}) ->
    case EmailOrUid of
        {email, Email} ->
            case StorageModule:load_by_email(Email, StorageState) of
                {ok, Account} -> 
                    {ok, Account};
                not_found -> not_found
            end;
        {uid, Uid} ->
            case StorageModule:load_by_uid(Uid, StorageState) of
                {ok, #account{deleted = false} = Account} -> 
                    {ok, Account};
                {ok, #account{deleted = true}} -> 
                    not_found;
                not_found -> not_found
            end
    end.

get_account_by_email(Email, State) ->
    case get_account_by_email(Email, include_logically_deleted, State) of
        {ok, #account{deleted = false} = Account} -> {ok, Account};
        {ok, #account{deleted = true}} -> not_found;
        not_found -> not_found
    end.

get_account_by_email(Email, include_logically_deleted, #state{storage_module = StorageModule} = State) ->
    case StorageModule:load_by_email(Email, State#state.storage_state) of
        {ok, Account} -> {ok, Account};
        not_found -> not_found
    end.

get_account_by_uid(Uid, State) ->
    case get_account_by_uid(Uid, include_logically_deleted, State) of
        {ok, #account{deleted = false} = Account} -> {ok, Account};
        {ok, #account{deleted = true}} -> not_found;
        not_found -> not_found
    end.

get_account_by_uid(Uid, include_logically_deleted, #state{storage_module = StorageModule} = State) ->
    case StorageModule:load_by_uid(Uid, State#state.storage_state) of
        {ok, Account} -> {ok, Account};
        not_found -> not_found
    end.

email_exists(Email, #state{storage_module = StorageModule} = State) ->
    case StorageModule:load_by_email(Email, State#state.storage_state) of
        {ok, _Account} -> true;
        not_found -> false
    end.

account_to_map(Account) ->
    #{
        uid => Account#account.uid,
        avatars => Account#account.avatars,
        extra => Account#account.extra,
        updated_at => Account#account.updated_at,
        created_at => Account#account.created_at
    }.
