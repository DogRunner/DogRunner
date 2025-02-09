CREATE TABLE IF NOT EXISTS dogruns (
    dogrun_id serial primary key,
    place_id varchar(256),
    dogrun_manager_id bigint,
    name varchar(256),
    address varchar(256),
    latitude decimal(18, 15),
    longitude decimal(18, 15),
    postcode varchar(8),
    tel varchar(18),
    url varchar(256),
    business_hour_desc varchar(512),
    description text,
    is_managed boolean,
    reg_at timestamp not null,
    upd_at timestamp not null
);
