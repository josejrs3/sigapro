-- Execute este arquivo no SQL Editor do Supabase.
-- O acesso Master continua usando Supabase Auth.
-- Os usuários da equipe usam esta autenticação própria, sem senha no localStorage.

create extension if not exists pgcrypto;

alter table public.perfis
    add column if not exists password_hash text;

drop function if exists public.admin_save_profile(uuid, uuid, text, text, text, text, text, text);

create or replace function public.admin_save_profile(
    p_id uuid,
    p_loja_id uuid,
    p_nome text,
    p_cargo text,
    p_username text,
    p_slug text,
    p_full_slug text,
    p_password text default null
)
returns table (
    id uuid,
    loja_id uuid,
    nome text,
    cargo text,
    username text,
    slug text,
    full_slug text,
    created_at timestamptz
)
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
    v_created_at timestamptz;
    v_cargo_sql text;
begin
    if auth.uid() is null then
        raise exception 'Acesso administrativo exige autenticação';
    end if;

    v_created_at := now();
    select p.created_at into v_created_at
    from public.perfis as p
    where p.id = p_id;
    if v_created_at is null then
        v_created_at := now();
    end if;

    if p_password is not null and p_password !~ '^[0-9]+$' then
        raise exception 'A senha deve conter apenas números';
    end if;

    v_cargo_sql := quote_literal(p_cargo);

    execute format($sql$
        insert into public.perfis (
            id, loja_id, nome, cargo, username, slug, full_slug, password_hash, created_at
        ) values (
            $1, $2, $3, %s, $4, $5, $6, $7, $8
        )
        on conflict (id) do update set
            loja_id = excluded.loja_id,
            nome = excluded.nome,
            cargo = excluded.cargo,
            username = excluded.username,
            slug = excluded.slug,
            full_slug = excluded.full_slug,
            password_hash = case
                when $9 is null then public.perfis.password_hash
                else excluded.password_hash
            end
    $sql$, v_cargo_sql)
    using p_id, p_loja_id, p_nome, p_username, p_slug, p_full_slug,
        case when p_password is null then null else crypt(p_password, gen_salt('bf', 10)) end,
        v_created_at, p_password;

    return query
        select p.id, p.loja_id, p.nome, p.cargo, p.username, p.slug, p.full_slug, p.created_at
        from public.perfis p
        where p.id = p_id;
end;
$$;

drop function if exists public.verify_profile_password(uuid, text);

create or replace function public.verify_profile_password(
    p_profile_id uuid,
    p_password text
)
returns table (
    id uuid,
    loja_id uuid,
    nome text,
    cargo text,
    username text,
    slug text,
    full_slug text,
    created_at timestamptz
)
language sql
security definer
set search_path = public, extensions
as $$
    select p.id, p.loja_id, p.nome, p.cargo, p.username, p.slug, p.full_slug, p.created_at
    from public.perfis p
    where p.id = p_profile_id
      and p_password is not null
      and p_password ~ '^[0-9]+$'
      and p.password_hash is not null
      and p.password_hash = crypt(p_password, p.password_hash);
$$;

revoke all on function public.admin_save_profile(uuid, uuid, text, text, text, text, text, text) from public;
revoke all on function public.verify_profile_password(uuid, text) from public;
grant execute on function public.admin_save_profile(uuid, uuid, text, text, text, text, text, text) to authenticated;
grant execute on function public.verify_profile_password(uuid, text) to anon, authenticated;

-- Não permita leitura pública do hash.
revoke select on public.perfis from anon;
grant select (id, loja_id, nome, cargo, username, slug, full_slug, created_at) on public.perfis to anon, authenticated;
