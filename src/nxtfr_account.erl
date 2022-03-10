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
    add_avatar/2,
    lookup/1,
    lookup/2,
    update_email/2,
    update_password/2,
    update_extra/2,
    validate/2,
    delete/1,
    delete/2
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

-spec read(EmailOrUid :: {email, Email :: binary} | {uid, Uid :: binary}) -> {ok, Account :: map() | {error, not_found}}.
read(EmailOrUid) ->
    gen_server:call(?MODULE, {read, EmailOrUid}).

-spec add_avatar(EmailOrUid :: {email, Email :: binary} | {uid, Uid :: binary}, AvatarUid :: binary()) -> {ok, added} | {error, not_found}.
add_avatar(EmailOrUid, AvatarUid) ->
    gen_server:call(?MODULE, {add_avatar, EmailOrUid, AvatarUid}).

-spec lookup(EmailOrUid :: {email, Email :: binary} | {uid, Uid :: binary}) -> {ok, Uid :: binary() | {error, not_found}}.
lookup(EmailOrUid) ->
    gen_server:call(?MODULE, {lookup, EmailOrUid}).

-spec lookup(EmailOrUid :: {email, Email :: binary} | {uid, Uid :: binary}, include_logically_deleted) -> {ok, Uid :: binary() | {error, not_found}}.
lookup(EmailOrUid, include_logically_deleted) ->
    gen_server:call(?MODULE, {lookup, EmailOrUid, include_logically_deleted}).

-spec update_email(EmailOrUid :: {email, Email :: binary} | {uid, Uid :: binary}, NewEmail :: binary()) -> {ok, updated} | {error, not_found} | {error, email_already_exists}.
update_email(EmailOrUid, NewEmail) ->
    gen_server:call(?MODULE, {update_email, EmailOrUid, NewEmail}).

-spec update_password(EmailOrUid :: {email, Email :: binary} | {uid, Uid :: binary}, NewEmail :: atom()) -> {ok, updated} | {error, not_found}.
update_password(EmailOrUid, NewPassword) ->
    gen_server:call(?MODULE, {update_password, EmailOrUid, NewPassword}).

-spec update_extra(EmailOrUid :: {email, Email :: binary} | {uid, Uid :: binary}, Extra :: any()) -> {ok, updated} | {error, not_found}.
update_extra(EmailOrUid, NewExtra) ->
    gen_server:call(?MODULE, {update_extra, EmailOrUid, NewExtra}).

-spec validate(EmailOrUid :: {email, Email :: binary} | {uid, Uid :: binary}, Password :: binary()) -> {ok, validation_success} | {error, validation_failure} | {error, not_found}.
validate(EmailOrUid, Password) ->
    gen_server:call(?MODULE, {validate, EmailOrUid, Password}).

-spec delete(EmailOrUid :: {email, Email :: binary} | {uid, Uid :: binary}) -> {ok, deleted} | {error, not_found}.
delete(EmailOrUid) ->
    gen_server:call(?MODULE, {delete, EmailOrUid}).

-spec delete(EmailOrUid :: {email, Email :: binary} | {uid, Uid :: binary}, logical_delete) -> {ok, deleted} | {error, not_found}.
delete(EmailOrUid, logical_delete) ->
    gen_server:call(?MODULE, {delete, EmailOrUid, logical_delete}).

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
    case email_exists(Email, State) of
        true -> 
            {reply, {error, email_already_exists}, State};
        false ->
            {ok, Account} = create_account(Email, Password, Extra, State),
            {reply, {ok, Account#account.uid}, State}
    end;

handle_call({add_avatar, EmailOrUid, AvatarUid}, _From, #state{storage_module = StorageModule} = State) ->
    case get_account(EmailOrUid, State) of
        {ok, #account{avatars = Avatars} = Account} ->
            case lists:member(AvatarUid, Avatars) of
                true -> 
                    {reply, {ok, already_added}, State};
                false -> 
                    UpdatedAccount = Account#account{
                        avatars = [AvatarUid | Avatars],
                        updated_at = get_rfc3339_time()
                    },
                    {ok, saved} = StorageModule:save(UpdatedAccount, State#state.storage_state),
                    {reply, {ok, added}, State}
            end;
        not_found ->
            {reply, {error, not_found}, State}
    end;

handle_call({read, EmailOrUid}, _From, State) ->
    case get_account(EmailOrUid, State) of
        {ok, Account} ->
            {reply, {ok, account_to_map(Account)}, State};
        not_found ->
            {reply, {error, not_found}, State}
    end;

handle_call({lookup, EmailOrUid}, _From, State) ->
    case get_account(EmailOrUid, State) of
        {ok, Account} ->
            {reply, {ok, Account#account.uid}, State};
        not_found ->
            {reply, {error, not_found}, State}
    end;

handle_call({lookup, EmailOrUid, include_logically_deleted}, _From, State) ->
    case get_account(EmailOrUid, include_logically_deleted, State) of
        {ok, Account} ->
            {reply, {ok, Account}, State};
        not_found ->
            {reply, {error, not_found}, State}
    end;

handle_call({update_email, EmailOrUid, NewEmail}, _From, #state{storage_module = StorageModule} = State) ->
    case email_exists(NewEmail, State) of
        true ->
            {reply, {error, email_already_exists}, State};
        false ->
            case get_account(EmailOrUid, State) of
                {ok, Account} ->
                    UpdatedAccount = Account#account{
                        email = NewEmail,
                        updated_at = get_rfc3339_time()
                    },
                    {ok, saved} = StorageModule:save(UpdatedAccount, State#state.storage_state),
                    {reply, {ok, updated}, State};
                not_found ->
                    {reply, {error, not_found}, State}
            end
    end;

handle_call(
        {update_password, EmailOrUid, NewPassword},
        _From,
        #state{storage_module = StorageModule, crypto_module = CryptoModule} = State) ->
    case get_account(EmailOrUid, State) of
        {ok, Account} ->
            {ok, NewPasswordHash} = CryptoModule:hash_password(NewPassword, State#state.crypto_state),
            UpdatedAccount = Account#account{
                password_hash = NewPasswordHash,
                updated_at = get_rfc3339_time()
            },
            {ok, saved} = StorageModule:save(UpdatedAccount, State#state.storage_state),
            {reply, {ok, updated}, State};
        not_found ->
            {reply, {error, not_found}, State}
    end;

handle_call({update_extra, EmailOrUid, NewExtra}, _From, #state{storage_module = StorageModule} = State) ->
    case get_account(EmailOrUid, State) of
        {ok, Account} ->
            UpdatedAccount = Account#account{
                extra = NewExtra,
                updated_at = get_rfc3339_time()
            },
            {ok, saved} = StorageModule:save(UpdatedAccount, State#state.storage_state),
            {reply, {ok, updated}, State};
        not_found ->
            {reply, {error, not_found}, State}
    end;

handle_call({validate, EmailOrUid, Password}, _From, #state{crypto_module = CryptoModule} = State) ->
    case get_account(EmailOrUid, State) of
        {ok, #account{password_hash = PasswordHash}} ->
            %% ValidationResult returns {ok, validation_success} | error, validation_failure}
            ValidationResult = CryptoModule:validate_password(Password, PasswordHash, State#state.crypto_state),
            {reply, ValidationResult, State};
        not_found ->
            {reply, {error, not_found}, State}
    end;

handle_call({delete, EmailOrUid}, _From, #state{storage_module = StorageModule} = State) ->
    case get_account(EmailOrUid, State) of
        {ok, #account{uid = Uid}} ->
            {ok, deleted} = StorageModule:delete(Uid, State#state.storage_state),
            {reply, {ok, deleted}, State};
        not_found ->
            {reply, {error, not_found}, State}
    end;

handle_call({delete, EmailOrUid, logical_delete}, _From, #state{storage_module = StorageModule} = State) ->
    case get_account(EmailOrUid, include_logically_deleted, State) of
        {ok, #account{uid = Uid}} ->
            {ok, deleted} = StorageModule:logical_delete(Uid, State#state.storage_state),
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

get_account(EmailOrUid, include_logically_deleted, State) ->
    case read_account_from_storage(EmailOrUid, State) of
        {ok, #account{deleted = true} = Account} -> {ok, Account};
        {ok, Account} -> {ok, Account};
        not_found -> not_found
    end.

read_account_from_storage(EmailOrUid, #state{storage_module = StorageModule, storage_state = StorageState}) ->
    case EmailOrUid of
        {email, Email} ->
            case StorageModule:load_by_email(Email, StorageState) of
                {ok, Account} -> 
                    {ok, Account};
                not_found ->
                    not_found
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

email_exists(Email, #state{storage_module = StorageModule} = State) ->
    case StorageModule:load_by_email(Email, State#state.storage_state) of
        {ok, _Account} -> true;
        not_found -> false
    end.

account_to_map(Account) ->
    #{
        uid => Account#account.uid,
        email => Account#account.email,
        avatars => Account#account.avatars,
        extra => Account#account.extra,
        updated_at => Account#account.updated_at,
        created_at => Account#account.created_at
    }.
