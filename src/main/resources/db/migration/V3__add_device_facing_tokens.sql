alter table registered_devices
    add column enrollment_token_hash varchar(64),
    add column enrollment_token_expires_at timestamptz;

alter table auth_sessions
    add column device_response_token varchar(255),
    add column device_response_token_hash varchar(64),
    add column device_response_token_expires_at timestamptz;

create index idx_registered_devices_enrollment_token_expires_at
    on registered_devices (enrollment_token_expires_at);

create index idx_auth_sessions_device_response_token_expires_at
    on auth_sessions (device_response_token_expires_at);
