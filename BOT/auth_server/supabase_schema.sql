CREATE TABLE IF NOT EXISTS public.auth_codes (
    code_hash text PRIMARY KEY,
    discord_user_id text NOT NULL,
    expires_at timestamptz NOT NULL,
    used boolean NOT NULL DEFAULT false
);

CREATE TABLE IF NOT EXISTS public.licenses (
    discord_user_id text PRIMARY KEY,
    device_id text,
    active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.sessions (
    token_hash text PRIMARY KEY,
    discord_user_id text NOT NULL REFERENCES public.licenses(discord_user_id),
    device_id text NOT NULL,
    expires_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS sessions_user_idx
    ON public.sessions(discord_user_id);

ALTER TABLE public.auth_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.licenses ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sessions ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON public.auth_codes, public.licenses, public.sessions
    FROM anon, authenticated;
GRANT ALL ON public.auth_codes, public.licenses, public.sessions
    TO service_role;

CREATE OR REPLACE FUNCTION public.register_auth_code(
    p_discord_user_id text,
    p_code_hash text,
    p_expires_days integer
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    IF p_expires_days < 1 OR p_expires_days > 365 THEN
        RAISE EXCEPTION 'AUTH_INVALID_EXPIRY';
    END IF;

    DELETE FROM public.auth_codes
    WHERE discord_user_id = p_discord_user_id AND NOT used;

    INSERT INTO public.auth_codes(code_hash, discord_user_id, expires_at)
    VALUES (
        p_code_hash,
        p_discord_user_id,
        now() + make_interval(days => p_expires_days)
    );
EXCEPTION WHEN unique_violation THEN
    RAISE EXCEPTION 'AUTH_CODE_DUPLICATE';
END;
$$;

CREATE OR REPLACE FUNCTION public.redeem_auth_code(
    p_code_hash text,
    p_device_id text,
    p_token_hash text
)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_code public.auth_codes%ROWTYPE;
    v_license public.licenses%ROWTYPE;
BEGIN
    SELECT * INTO v_code
    FROM public.auth_codes
    WHERE code_hash = p_code_hash AND NOT used AND expires_at > now()
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'AUTH_INVALID_CODE';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended(v_code.discord_user_id, 0));

    SELECT * INTO v_license
    FROM public.licenses
    WHERE discord_user_id = v_code.discord_user_id
    FOR UPDATE;

    IF FOUND AND NOT v_license.active THEN
        RAISE EXCEPTION 'AUTH_REVOKED';
    END IF;
    IF FOUND AND v_license.device_id IS NOT NULL
       AND v_license.device_id <> p_device_id THEN
        RAISE EXCEPTION 'AUTH_DEVICE_MISMATCH';
    END IF;

    INSERT INTO public.licenses(discord_user_id, device_id, active)
    VALUES (v_code.discord_user_id, p_device_id, true)
    ON CONFLICT (discord_user_id) DO UPDATE
        SET device_id = EXCLUDED.device_id, active = true;

    UPDATE public.auth_codes SET used = true WHERE code_hash = p_code_hash;

    INSERT INTO public.sessions(token_hash, discord_user_id, device_id, expires_at)
    VALUES (
        p_token_hash,
        v_code.discord_user_id,
        p_device_id,
        now() + interval '30 days'
    );

    RETURN v_code.discord_user_id;
END;
$$;

CREATE OR REPLACE FUNCTION public.verify_auth_session(
    p_token_hash text,
    p_device_id text
)
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT s.discord_user_id
    FROM public.sessions AS s
    JOIN public.licenses AS l USING (discord_user_id)
    WHERE s.token_hash = p_token_hash
      AND s.device_id = p_device_id
      AND s.expires_at > now()
      AND l.device_id = p_device_id
      AND l.active;
$$;

CREATE OR REPLACE FUNCTION public.reset_auth_device(p_discord_user_id text)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    UPDATE public.licenses SET device_id = NULL
    WHERE discord_user_id = p_discord_user_id;
    DELETE FROM public.sessions WHERE discord_user_id = p_discord_user_id;
    DELETE FROM public.auth_codes WHERE discord_user_id = p_discord_user_id;
END;
$$;

CREATE OR REPLACE FUNCTION public.revoke_auth_user(p_discord_user_id text)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    INSERT INTO public.licenses(discord_user_id, device_id, active)
    VALUES (p_discord_user_id, NULL, false)
    ON CONFLICT (discord_user_id) DO UPDATE SET active = false;
    DELETE FROM public.sessions WHERE discord_user_id = p_discord_user_id;
    DELETE FROM public.auth_codes WHERE discord_user_id = p_discord_user_id;
END;
$$;

REVOKE ALL ON FUNCTION public.register_auth_code(text, text, integer)
    FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.redeem_auth_code(text, text, text)
    FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.verify_auth_session(text, text)
    FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.reset_auth_device(text)
    FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.revoke_auth_user(text)
    FROM PUBLIC, anon, authenticated;

GRANT EXECUTE ON FUNCTION public.register_auth_code(text, text, integer)
    TO service_role;
GRANT EXECUTE ON FUNCTION public.redeem_auth_code(text, text, text)
    TO service_role;
GRANT EXECUTE ON FUNCTION public.verify_auth_session(text, text)
    TO service_role;
GRANT EXECUTE ON FUNCTION public.reset_auth_device(text)
    TO service_role;
GRANT EXECUTE ON FUNCTION public.revoke_auth_user(text)
    TO service_role;