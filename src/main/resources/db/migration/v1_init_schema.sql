create table app_users (
                           id uuid primary key,
                           external_user_id varchar(128) not null unique,
                           display_name varchar(255),
                           created_at timestamptz not null
);

create table registered_devices (
                                    id uuid primary key,
                                    user_id uuid not null references app_users(id),
                                    device_label varchar(255) not null,
                                    service_id varchar(128) not null,
                                    status varchar(32) not null,
                                    secret_ciphertext text not null,
                                    secret_nonce varchar(128) not null,
                                    algorithm varchar(16) not null,
                                    digits integer not null,
                                    period_seconds integer not null,
                                    created_at timestamptz not null,
                                    confirmed_at timestamptz,
                                    revoked_at timestamptz,
                                    last_used_at timestamptz
);

create index idx_registered_devices_user_status
    on registered_devices (user_id, status);

create table auth_sessions (
                               id uuid primary key,
                               user_id uuid not null references app_users(id),
                               device_id uuid not null references registered_devices(id),
                               challenge varchar(128) not null unique,
                               status varchar(32) not null,
                               first_factor_ref varchar(255),
                               created_at timestamptz not null,
                               expires_at timestamptz not null,
                               verified_at timestamptz,
                               attempt_count integer not null,
                               max_attempts integer not null,
                               accepted_response_hash varchar(64)
);

create index idx_auth_sessions_user_status
    on auth_sessions (user_id, status);

create index idx_auth_sessions_device_status
    on auth_sessions (device_id, status);

create index idx_auth_sessions_expires_at
    on auth_sessions (expires_at);