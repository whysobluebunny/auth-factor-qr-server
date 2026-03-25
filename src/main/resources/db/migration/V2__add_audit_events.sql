create table audit_events (
                              id uuid primary key,
                              event_type varchar(64) not null,
                              outcome varchar(16) not null,
                              external_user_id varchar(128),
                              device_id uuid,
                              session_id uuid,
                              details text,
                              occurred_at timestamptz not null
);

create index idx_audit_events_external_user_id_occurred_at
    on audit_events (external_user_id, occurred_at desc);

create index idx_audit_events_device_id_occurred_at
    on audit_events (device_id, occurred_at desc);

create index idx_audit_events_session_id_occurred_at
    on audit_events (session_id, occurred_at desc);
