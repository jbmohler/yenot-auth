create extension if not exists "uuid-ossp";

drop table if exists controls;
drop table if exists users cascade;
drop table if exists roles cascade;
drop table if exists activities cascade;
drop table if exists sessions cascade;
drop table if exists userroles cascade;
drop table if exists roleactivities cascade;

create table controls (
  data_name varchar(50)
);
create unique index singleton_idx on controls((true));

-- auth tables

create table users (
  id uuid primary key default uuid_generate_v1mc(),
  username varchar(20) not null unique,
  pwhash varchar(60) CHECK (pwhash ~ '^[\x21-\x7F]*$'),
  pinhash varchar(60) CHECK (pwhash ~ '^[\x21-\x7F]*$'),
  target_2fa json,
  full_name text,
  descr text,
  inactive boolean not null default false,
  check ((pinhash is null and target_2fa is null) or (pinhash is not null and target_2fa is not null))
);

create table roles (
  id uuid primary key default uuid_generate_v1mc(),
  role_name character varying(40) unique,
  sort integer
);

create table activities (
  id uuid primary key default uuid_generate_v1mc(),
  act_name character varying(80) unique,
  description text,
  url character varying(500),
  note text
);

create table devicetokens (
  id character(32) primary key,
  userid uuid references users(id) not null,
  device_name text,
  tokenhash varchar(60) CHECK (tokenhash ~ '^[\x21-\x7F]*$'),
  issued timestamp without time zone not null,
  inactive boolean not null default false,
  expires timestamp without time zone not null
);

create table sessions (
  id character(24) primary key,
  userid uuid references users(id) not null,
  ipaddress character varying(45),
  devtok_id character(32) references devicetokens(id),
  refreshed timestamp without time zone not null,
  inactive boolean not null default false,
  pin_2fa char(6)
);

create table userroles (
  roleid uuid not null references roles(id),
  userid uuid not null references users(id),
  constraint userroles_pkey primary key (roleid, userid)
);

create table roleactivities (
  roleid uuid not null references roles(id),
  activityid uuid not null references activities(id),
  permitted boolean default true,
  dashboard boolean default false not null,
  dashprompts text, -- want it to be json
  constraint roleactivities_pkey primary key (roleid, activityid)
);
