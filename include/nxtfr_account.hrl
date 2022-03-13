-record(account, {
    uid :: binary(),
    email :: binary(),
    password_hash :: binary(),
    avatars :: list(),
    friends :: list(),
    extra :: any(),
    created_at :: binary(),
    updated_at :: binary(),
    deleted_at :: binary(),
    restored_at :: binary(),
    deleted = false :: true | false}).

-record(account_history, {
    uid :: binary(),
    actions :: list()}).

-type account() :: #account{}. 
-type account_history() :: #account_history{}. 