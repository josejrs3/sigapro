-- Execute este arquivo no SQL Editor do Supabase.
-- O acesso Master continua usando Supabase Auth.
-- Os usuários da equipe usam esta autenticação própria, sem senha no localStorage.

create extension if not exists pgcrypto;

create table if not exists public.humor_registros (
    id uuid primary key default gen_random_uuid(),
    loja_id uuid not null references public.lojas(id) on delete cascade,
    vendedor_id uuid not null references public.perfis(id) on delete cascade,
    data date not null,
    humor text not null,
    updated_at timestamptz not null default now()
);

create unique index if not exists humor_registros_vendedor_data_key
    on public.humor_registros (vendedor_id, data);

grant select, insert, update, delete on public.humor_registros to anon, authenticated;

create table if not exists public.prospeccao_listas (
    id uuid primary key default gen_random_uuid(),
    loja_id uuid not null references public.lojas(id) on delete cascade,
    nome text not null,
    dias_disponiveis jsonb not null default '[]'::jsonb,
    contatos jsonb not null default '[]'::jsonb,
    mensagens jsonb not null default '[]'::jsonb,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

grant select, insert, update, delete on public.prospeccao_listas to anon, authenticated;

-- Compatibilidade com a coluna antiga de senha, caso ainda exista no projeto.
do $$
begin
    if to_regclass('public.perfis') is not null
       and exists (
           select 1
           from information_schema.columns
           where table_schema = 'public'
             and table_name = 'perfis'
             and column_name = 'password'
       ) then
        alter table public.perfis alter column password drop not null;
    end if;
end;
$$;

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
    v_cargo public.perfis.cargo%type;
    v_password_hash text;
begin
    if auth.uid() is null then
        raise exception 'Acesso administrativo exige autenticação';
    end if;

    if p_password is not null and p_password !~ '^[0-9]+$' then
        raise exception 'A senha deve conter apenas números';
    end if;

    select p.created_at
    into v_created_at
    from public.perfis as p
    where p.id = $1;

    v_created_at := coalesce(v_created_at, now());
    v_cargo := p_cargo;
    v_password_hash := case
        when p_password is null then null
        else crypt(p_password, gen_salt('bf', 10))
    end;

    update public.perfis as current_profile
    set loja_id = p_loja_id,
        nome = p_nome,
        cargo = v_cargo,
        username = p_username,
        slug = p_slug,
        full_slug = p_full_slug,
        password_hash = case
            when p_password is null then current_profile.password_hash
            else v_password_hash
        end
    where current_profile.id = p_id;

    if not found then
        insert into public.perfis (
            id, loja_id, nome, cargo, username, slug, full_slug, password_hash, created_at
        ) values (
            p_id, p_loja_id, p_nome, v_cargo, p_username, p_slug, p_full_slug,
            v_password_hash, v_created_at
        );
    end if;

    return query
        select profile.id, profile.loja_id, profile.nome, profile.cargo::text, profile.username, profile.slug, profile.full_slug, profile.created_at
        from public.perfis as profile
        where profile.id = $1;
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
    select p.id, p.loja_id, p.nome, p.cargo::text, p.username, p.slug, p.full_slug, p.created_at
    from public.perfis as p
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
