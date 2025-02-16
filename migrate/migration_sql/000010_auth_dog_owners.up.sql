CREATE TABLE IF NOT EXISTS auth_dog_owners (
    auth_dog_owner_id serial primary key,         -- PK
    dog_owner_id bigint not null,                 -- dog_ownersへの外部キー
    access_token varchar(512),                    -- アクセストークン（OAuth 認証の場合のみ）
    refresh_token varchar(512),                   -- リフレッシュトークン（OAuth 認証の場合のみ）
    access_token_expiration timestamp,            -- アクセストークンの有効期限
    refresh_token_expiration timestamp,           -- リフレッシュトークンの有効期限（オプション）
    jwt_id varchar(45),
    refresh_iwt_id varchar(45),
    si_refresh_token varchar(512),
    login_at timestamp
);
