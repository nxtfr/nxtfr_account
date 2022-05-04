-module(nxtfr_account).
-author("christian@flodihn.se").
-behaviour(gen_server).

-include("nxtfr_account.hrl").

%% External exports
-export([
    start_link/0,
    create/2,
    create/3,
    fetch_by_email/1,
    fetch_by_uid/1,
    fetch_by_email/2,
    fetch_by_uid/2,
    update/1,
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

create(Password, Extra) ->
    gen_server:call(?MODULE, {create, Password, Extra}).

create(Email, Password, Extra) ->
    gen_server:call(?MODULE, {create, Email, Password, Extra}).

fetch_by_email(Email) ->
    gen_server:call(?MODULE, {fetch_by_email, Email}).

fetch_by_uid(Uid) ->
    gen_server:call(?MODULE, {fetch_by_uid, Uid}).

fetch_by_email(Email, include_logically_deleted) ->
    gen_server:call(?MODULE, {fetch_by_email, Email, include_logically_deleted}).

fetch_by_uid(Uid, include_logically_deleted) ->
    gen_server:call(?MODULE, {fetch_by_uid, Uid, include_logically_deleted}).

update(#account{} = Account) ->
    gen_server:call(?MODULE, {update, Account}).

update_email_by_email(OldEmail, NewEmail) ->
    gen_server:call(?MODULE, {update_email_by_email, OldEmail, NewEmail}).

update_email_by_uid(Uid, NewEmail) ->
    gen_server:call(?MODULE, {update_email_by_uid, Uid, NewEmail}).

update_password_by_email(Email, NewPassword) ->
    gen_server:call(?MODULE, {update_password_by_email, Email, NewPassword}).

update_password_by_uid(Uid, NewPassword) ->
    gen_server:call(?MODULE, {update_password_by_uid, Uid, NewPassword}).

update_extra_by_email(Email, NewExtra) ->
    gen_server:call(?MODULE, {update_extra_by_email, Email, NewExtra}).

update_extra_by_uid(Uid, NewExtra) ->
    gen_server:call(?MODULE, {update_extra_by_uid, Uid, NewExtra}).

validate_by_email(Email, Password) ->
    gen_server:call(?MODULE, {validate_by_email, Email, Password}).

validate_by_uid(Uid, Password) ->
    gen_server:call(?MODULE, {validate_by_uid, Uid, Password}).

delete_by_email(Email) ->
    gen_server:call(?MODULE, {delete_by_email, Email}).

delete_by_uid(Uid) ->
    gen_server:call(?MODULE, {delete_by_uid, Uid}).

delete_by_email(Email, logical_delete) ->
    gen_server:call(?MODULE, {delete_by_email, Email, logical_delete}).

delete_by_uid(Uid, logical_delete) ->
    gen_server:call(?MODULE, {delete_by_uid, Uid, logical_delete}).

init([]) ->
    application:start(nxtfr_event),
    nxtfr_event:add_global_handler(nxtfr_account, nxtfr_account_event_handler),
    {ok, StorageModule} = application:get_env(nxtfr_account, storage_module),
    {ok, CryptoModule} = application:get_env(nxtfr_account, crypto_module),
    {ok, AutoDiscoveryGroup} = application:get_env(nxtfr_account, autodiscovery_group),
    nxtfr_autodiscovery:join_group(AutoDiscoveryGroup),
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
    {reply, {ok, Account}, State};

handle_call({create, Email, Password, Extra}, _From, State) ->
    case get_account_by_email(Email, include_logically_deleted, State) of
        {ok, _ExistingAccount} -> 
            {reply, {error, email_already_exists}, State};
        not_found ->
            {ok, Account} = create_account(Email, Password, Extra, State),
            {reply, {ok, Account}, State}
    end;

handle_call({fetch_by_email, Email}, _From, State) ->
    case get_account_by_email(Email, State) of
        {ok, Account} ->
            {reply, {ok, Account}, State};
        not_found ->
            {reply, {error, not_found}, State}
    end;

handle_call({fetch_by_uid, Uid}, _From, State) ->
    case get_account_by_uid(Uid, State) of
        {ok, Account} ->
            {reply, {ok, Account}, State};
        not_found ->
            {reply, not_found, State}
    end;

handle_call({fetch_by_email, Email, include_logically_deleted}, _From, State) ->
    case get_account_by_email(Email, include_logically_deleted, State) of
        {ok, Account} ->
            {reply, {ok, Account}, State};
        not_found ->
            {reply, {error, not_found}, State}
    end;

handle_call({fetch_by_uid, Uid, include_logically_deleted}, _From, State) ->
    case get_account_by_uid(Uid, State) of
        {ok, Account} ->
            {reply, {ok, Account}, State};
        not_found ->
            {reply, not_found, State}
    end;

handle_call({update, Account}, _From, #state{storage_module = StorageModule} = State) ->
    case StorageModule:save(Account#account{updated_at = get_rfc3339_time()}, State#state.storage_state) of
        {ok, saved} -> {reply, {ok, updated}, State};
        not_found -> {reply, {error, not_found}, State}
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
            {reply, {error, wrong_email_or_password}, State}
    end;

handle_call({validate_by_uid, Uid, Password}, _From, #state{crypto_module = CryptoModule} = State) ->
    case get_account_by_uid(Uid, State) of
        {ok, #account{password_hash = PasswordHash, deleted = false}} ->
            %% ValidationResult returns {ok, validation_success} | error, validation_failure}
            ValidationResult = CryptoModule:validate_password(Password, PasswordHash, State#state.crypto_state),
            {reply, ValidationResult, State};
        not_found ->
            {reply, {error, wrong_uid_or_password}, State}
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
    DeleteResult = StorageModule:delete(Uid, State#state.storage_state),
    {reply, DeleteResult, State};

handle_call({delete_by_uid, Uid, logical_delete}, _From, #state{storage_module = StorageModule} = State) ->
    DeleteResult = StorageModule:logical_delete(Uid, State#state.storage_state),
    {reply, DeleteResult, State};

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
    Account = #{
        uid => make_uid(),
        email => Email,
        password_hash => PasswordHash,
        characters => [],
        extra => Extra,
        created_at => get_rfc3339_time()
    },
    {ok, saved} = StorageModule:save(Account, State#state.storage_state),
    {ok, Account}.

get_account_by_email(Email, State) ->
    case get_account_by_email(Email, include_logically_deleted, State) of
        {ok, #account{deleted = false} = Account} ->
            {ok, Account};
        {ok, #account{deleted = true}} ->
            not_found;
        not_found ->
            not_found
    end.

get_account_by_email(Email, include_logically_deleted, #state{storage_module = StorageModule} = State) ->
    case StorageModule:load_by_email(Email, State#state.storage_state) of
        {ok, Account} ->
            {ok, Account};
        not_found ->
            not_found
    end.

get_account_by_uid(Uid, State) ->
    case get_account_by_uid(Uid, include_logically_deleted, State) of
        {ok, #account{deleted = false} = Account} ->
            {ok, Account};
        {ok, #account{deleted = true}} ->
            not_found;
        not_found ->
            not_found
    end.

get_account_by_uid(Uid, include_logically_deleted, #state{storage_module = StorageModule} = State) ->
    case StorageModule:load_by_uid(Uid, State#state.storage_state) of
        {ok, Account} ->
            {ok, Account};
        not_found ->
            not_found
    end.

email_exists(Email, #state{storage_module = StorageModule} = State) ->
    case StorageModule:load_by_email(Email, State#state.storage_state) of
        {ok, _Account} -> true;
        not_found -> false
    end.