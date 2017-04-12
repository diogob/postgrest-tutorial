CREATE DATABASE tutorial;
\c tutorial

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- We put things inside the auth schema to hide
-- them from public view. Certain public procs/views will
-- refer to helpers and tables inside.
CREATE SCHEMA IF NOT EXISTS auth;

CREATE TABLE IF NOT EXISTS
auth.users (
  email    text primary key check ( email ~* '^.+@.+\..+$' ),
  pass     text not null check (length(pass) < 512),
  role     name not null check (length(role) < 512),
  verified boolean not null default false
  -- If you like add more columns, or a json column
);

CREATE OR REPLACE FUNCTION
auth.check_role_exists() RETURNS TRIGGER
  LANGUAGE plpgsql
  AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles AS r WHERE r.rolname = new.role) THEN
    RAISE foreign_key_violation USING message =
      'unknown database role: ' || new.role;
    RETURN NULL;
  END IF;
  RETURN new;
END
$$;

DROP TRIGGER IF EXISTS ensure_user_role_exists ON auth.users;
CREATE CONSTRAINT TRIGGER ensure_user_role_exists
  AFTER INSERT OR UPDATE ON auth.users
  FOR EACH ROW
  EXECUTE PROCEDURE auth.check_role_exists();

CREATE OR REPLACE FUNCTION
auth.encrypt_pass() RETURNS TRIGGER
  LANGUAGE plpgsql
  AS $$
BEGIN
  IF tg_op = 'INSERT' OR new.pass <> old.pass THEN
    new.pass = crypt(new.pass, gen_salt('bf'));
  END IF;
  RETURN new;
END
$$;

DROP TRIGGER IF EXISTS encrypt_pass ON auth.users;
CREATE TRIGGER encrypt_pass
  BEFORE INSERT OR UPDATE ON auth.users
  FOR EACH ROW
  EXECUTE PROCEDURE auth.encrypt_pass();

CREATE OR REPLACE FUNCTION
auth.user_role(email text, pass text) RETURNS name
LANGUAGE plpgsql
AS $$
BEGIN
  RETURN (
  SELECT role FROM auth.users
  WHERE users.email = user_role.email
  AND users.pass = crypt(user_role.pass, users.pass)
  );
END;
$$;

DROP TYPE IF EXISTS auth.jwt_claims CASCADE;
CREATE TYPE auth.jwt_claims AS (role text, email text);

CREATE FUNCTION auth.is_owner_or_admin(role text)
RETURNS boolean
LANGUAGE SQL
STABLE
AS $$
  SELECT current_setting('postgrest.claims.email') = role OR current_user = 'admin'
$$;

-- The following schema will be used to store all data coming from the frontend
CREATE SCHEMA IF NOT EXISTS recorder;

CREATE TABLE recorder.frontend_history(
  id serial PRIMARY KEY,
  payload json NOT NULL,
  email text REFERENCES auth.users
);

CREATE OR REPLACE FUNCTION recorder.frontend(msg json)
RETURNS void
LANGUAGE SQL
AS $$
INSERT INTO recorder.frontend_history (payload, email) VALUES ((msg->>'payload')::json, msg->'userClaims'->>'email');
$$;

/*
 * Public API
 */
CREATE OR REPLACE FUNCTION public.login(email text, pass text)
RETURNS auth.jwt_claims
SECURITY DEFINER
LANGUAGE plpgsql
AS $$
  DECLARE
    _role name;
    result auth.jwt_claims;
  BEGIN
    SELECT auth.user_role(email, pass) INTO _role;
    IF _role IS NULL THEN
      RAISE invalid_password USING message = 'invalid user or password';
    END IF;
    SELECT _role AS role, login.email AS email INTO result;
    RETURN result;
  END;
$$;

CREATE OR REPLACE VIEW public.users AS
SELECT
  email,
  '***'::text as pass,
  role,
  verified
FROM
  auth.users
WHERE
  auth.is_owner_or_admin(role);

CREATE OR REPLACE FUNCTION auth.insert_users()
RETURNS TRIGGER
SECURITY DEFINER
LANGUAGE plpgsql
AS $$
BEGIN
  INSERT INTO auth.users (email, pass, role)
  VALUES (NEW.email, NEW.pass, 'webuser');
  RETURN NEW;
END;
$$;

CREATE TRIGGER insert_users INSTEAD OF INSERT
ON public.users
FOR EACH ROW
EXECUTE PROCEDURE auth.insert_users();

-- People examples
CREATE SCHEMA IF NOT EXISTS tutorial;

CREATE TABLE tutorial.people (
  id serial not null primary key,
  name text not null,
  birthdate date not null,
  created_at timestamp not null default now()
);

CREATE TABLE tutorial.pets (
  id serial not null primary key,
  person_id int not null references tutorial.people,
  name text not null,
  created_at timestamp not null default now()
);

CREATE OR REPLACE VIEW public.people AS
SELECT * FROM tutorial.people;

CREATE OR REPLACE VIEW public.pets AS
SELECT * FROM tutorial.pets;

-- Roles and privileges
CREATE USER recorder PASSWORD 'development_password' NOINHERIT;
CREATE USER postgrest PASSWORD 'development_password' NOINHERIT;
CREATE ROLE anonymous;
CREATE ROLE webuser;
CREATE ROLE admin;
GRANT anonymous, webuser, admin TO postgrest;
GRANT EXECUTE ON FUNCTION public.login(text, text) TO anonymous;
GRANT INSERT, SELECT ON public.users TO anonymous;
GRANT SELECT ON public.people, public.pets TO anonymous;
GRANT ALL ON SCHEMA recorder TO recorder;
GRANT INSERT ON recorder.frontend_history TO recorder;
GRANT EXECUTE ON FUNCTION recorder.frontend(json) TO recorder;
GRANT USAGE ON SEQUENCE recorder.frontend_history_id_seq TO recorder;

-- Default claims
ALTER DATABASE tutorial SET postgrest.claims.email = '';

-- Sample DATA
INSERT INTO tutorial.people (id, name, birthdate) VALUES (1, 'Foo', '1990-01-01'), (2, 'Bar', '1992-10-21');
INSERT INTO tutorial.pets (person_id, name) VALUES (1, 'Foo Dog'), (2, 'Bar Cat');
