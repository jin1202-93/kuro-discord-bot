CREATE TABLE IF NOT EXISTS public.kuro_auth_codes_v2 (
    code_hash text PRIMARY KEY,
    license_id text NOT NULL,
    expires_at timestamptz NOT NULL,
    used boolean NOT NULL DEFAULT false
);

CREATE TABLE IF NOT EXISTS public.kuro_auth_licenses_v2 (
    license_id text PRIMARY KEY,
    device_id text,
    active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.kuro_auth_sessions_v2 (
    token_hash text PRIMARY KEY,
    license_id text NOT NULL REFERENCES public.kuro_auth_licenses_v2(license_id),
    device_id text NOT NULL,
    expires_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS kuro_auth_sessions_v2_license_idx
    ON public.kuro_auth_sessions_v2(license_id);

ALTER TABLE public.kuro_auth_codes_v2 ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.kuro_auth_licenses_v2 ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.kuro_auth_sessions_v2 ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON public.kuro_auth_codes_v2, public.kuro_auth_licenses_v2, public.kuro_auth_sessions_v2
    FROM anon, authenticated;
GRANT ALL ON public.kuro_auth_codes_v2, public.kuro_auth_licenses_v2, public.kuro_auth_sessions_v2
    TO service_role;

CREATE OR REPLACE FUNCTION public.issue_auth_code_v2(
    p_license_id text,
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

    INSERT INTO public.kuro_auth_licenses_v2(license_id)
    VALUES (p_license_id);

    INSERT INTO public.kuro_auth_codes_v2(code_hash, license_id, expires_at)
    VALUES (
        p_code_hash,
        p_license_id,
        now() + make_interval(days => p_expires_days)
    );
EXCEPTION WHEN unique_violation THEN
    RAISE EXCEPTION 'AUTH_CODE_DUPLICATE';
END;
$$;

CREATE OR REPLACE FUNCTION public.redeem_auth_code_v2(
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
    v_code public.kuro_auth_codes_v2%ROWTYPE;
    v_license public.kuro_auth_licenses_v2%ROWTYPE;
BEGIN
    SELECT * INTO v_code
    FROM public.kuro_auth_codes_v2
    WHERE code_hash = p_code_hash AND NOT used AND expires_at > now()
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'AUTH_INVALID_CODE';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended(v_code.license_id, 0));

    SELECT * INTO v_license
    FROM public.kuro_auth_licenses_v2
    WHERE license_id = v_code.license_id
    FOR UPDATE;

    IF FOUND AND NOT v_license.active THEN
        RAISE EXCEPTION 'AUTH_LICENSE_REVOKED';
    END IF;
    IF FOUND AND v_license.device_id IS NOT NULL
       AND v_license.device_id <> p_device_id THEN
        RAISE EXCEPTION 'AUTH_DEVICE_MISMATCH';
    END IF;

    UPDATE public.kuro_auth_licenses_v2
    SET device_id = p_device_id
    WHERE license_id = v_code.license_id;

    UPDATE public.kuro_auth_codes_v2 SET used = true WHERE code_hash = p_code_hash;

    INSERT INTO public.kuro_auth_sessions_v2(token_hash, license_id, device_id, expires_at)
    VALUES (
        p_token_hash,
        v_code.license_id,
        p_device_id,
        now() + interval '30 days'
    );

    RETURN v_code.license_id;
END;
$$;

CREATE OR REPLACE FUNCTION public.verify_auth_session_v2(
    p_token_hash text,
    p_device_id text
)
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT s.license_id
    FROM public.kuro_auth_sessions_v2 AS s
    JOIN public.kuro_auth_licenses_v2 AS l USING (license_id)
    WHERE s.token_hash = p_token_hash
      AND s.device_id = p_device_id
      AND s.expires_at > now()
      AND l.device_id = p_device_id
      AND l.active;
$$;

CREATE OR REPLACE FUNCTION public.reset_auth_device_v2(
    p_license_id text,
    p_code_hash text,
    p_expires_days integer
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    UPDATE public.kuro_auth_licenses_v2 SET device_id = NULL
    WHERE license_id = p_license_id AND active;
    IF NOT FOUND THEN
        IF EXISTS (SELECT 1 FROM public.kuro_auth_licenses_v2 WHERE license_id = p_license_id) THEN
            RAISE EXCEPTION 'AUTH_LICENSE_REVOKED';
        END IF;
        RAISE EXCEPTION 'AUTH_LICENSE_NOT_FOUND';
    END IF;

    DELETE FROM public.kuro_auth_sessions_v2 WHERE license_id = p_license_id;
    DELETE FROM public.kuro_auth_codes_v2 WHERE license_id = p_license_id;
    INSERT INTO public.kuro_auth_codes_v2(code_hash, license_id, expires_at)
    VALUES (p_code_hash, p_license_id, now() + make_interval(days => p_expires_days));
END;
$$;

CREATE OR REPLACE FUNCTION public.revoke_auth_user_v2(p_license_id text)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    UPDATE public.kuro_auth_licenses_v2 SET active = false
    WHERE license_id = p_license_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'AUTH_LICENSE_NOT_FOUND';
    END IF;
    DELETE FROM public.kuro_auth_sessions_v2 WHERE license_id = p_license_id;
    DELETE FROM public.kuro_auth_codes_v2 WHERE license_id = p_license_id;
END;
$$;

REVOKE ALL ON FUNCTION public.issue_auth_code_v2(text, text, integer)
    FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.redeem_auth_code_v2(text, text, text)
    FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.verify_auth_session_v2(text, text)
    FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.reset_auth_device_v2(text, text, integer)
    FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.revoke_auth_user_v2(text)
    FROM PUBLIC, anon, authenticated;

GRANT EXECUTE ON FUNCTION public.issue_auth_code_v2(text, text, integer)
    TO service_role;
GRANT EXECUTE ON FUNCTION public.redeem_auth_code_v2(text, text, text)
    TO service_role;
GRANT EXECUTE ON FUNCTION public.verify_auth_session_v2(text, text)
    TO service_role;
GRANT EXECUTE ON FUNCTION public.reset_auth_device_v2(text, text, integer)
    TO service_role;
GRANT EXECUTE ON FUNCTION public.revoke_auth_user_v2(text)
    TO service_role;