
-- CLAVE PUBLICA
-- Base inicial para Supabase
-- Ejecutar en el SQL Editor de Supabase

begin;

create extension if not exists pgcrypto;

-- 1. Organizaciones
create table if not exists public.organizations (
    id uuid primary key default gen_random_uuid(),
    name text not null,
    created_by uuid not null references auth.users(id) on delete restrict,
    created_at timestamptz not null default now()
);

-- 2. Perfil y permisos de cada usuario
create table if not exists public.profiles (
    user_id uuid primary key references auth.users(id) on delete cascade,
    organization_id uuid references public.organizations(id) on delete set null,
    full_name text not null default '',
    role text not null default 'member'
        check (role in ('owner', 'admin', 'member', 'viewer')),
    created_at timestamptz not null default now()
);

-- 3. Expedientes y procedimientos
create table if not exists public.cases (
    id uuid primary key default gen_random_uuid(),
    organization_id uuid not null
        references public.organizations(id) on delete cascade,
    procedure_number text not null default '',
    title text not null default '',
    status text not null default 'en análisis'
        check (status in ('en análisis', 'en proceso', 'completado')),
    data jsonb not null default '{}'::jsonb,
    created_by uuid not null references auth.users(id),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

-- 4. Tareas por integrante
create table if not exists public.case_tasks (
    id uuid primary key default gen_random_uuid(),
    case_id uuid not null references public.cases(id) on delete cascade,
    organization_id uuid not null
        references public.organizations(id) on delete cascade,
    assigned_to uuid references auth.users(id) on delete set null,
    title text not null,
    status text not null default 'en análisis'
        check (status in ('en análisis', 'en proceso', 'completado')),
    due_date date,
    completed_at timestamptz,
    created_at timestamptz not null default now()
);

-- 5. Historial de cambios
create table if not exists public.case_history (
    id uuid primary key default gen_random_uuid(),
    case_id uuid not null references public.cases(id) on delete cascade,
    organization_id uuid not null
        references public.organizations(id) on delete cascade,
    user_id uuid references auth.users(id) on delete set null,
    action text not null,
    details jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now()
);

-- Función interna: comprobar pertenencia a una organización
create or replace function public.is_org_member(org_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
    select exists (
        select 1
        from public.profiles p
        where p.user_id = (select auth.uid())
          and p.organization_id = org_id
    );
$$;

-- Función interna: comprobar permisos administrativos
create or replace function public.is_org_admin(org_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
    select exists (
        select 1
        from public.profiles p
        where p.user_id = (select auth.uid())
          and p.organization_id = org_id
          and p.role in ('owner', 'admin')
    );
$$;

-- Activar seguridad por fila
alter table public.organizations enable row level security;
alter table public.profiles enable row level security;
alter table public.cases enable row level security;
alter table public.case_tasks enable row level security;
alter table public.case_history enable row level security;

-- Organizaciones: sus miembros pueden consultarlas
drop policy if exists "org_read_members" on public.organizations;
create policy "org_read_members"
on public.organizations for select to authenticated
using (public.is_org_member(id) or created_by = (select auth.uid()));

-- Crear una organización con el usuario autenticado
drop policy if exists "org_create_self" on public.organizations;
create policy "org_create_self"
on public.organizations for insert to authenticated
with check (created_by = (select auth.uid()));

-- Perfiles: cada usuario ve su perfil y los administradores
-- pueden consultar perfiles de su organización
drop policy if exists "profiles_read_org" on public.profiles;
create policy "profiles_read_org"
on public.profiles for select to authenticated
using (
    user_id = (select auth.uid())
    or public.is_org_admin(organization_id)
);

-- Un usuario puede crear su perfil, pero no asignarse permisos
-- administrativos ni vincularse libremente a otra organización.
drop policy if exists "profiles_insert_self" on public.profiles;
create policy "profiles_insert_self"
on public.profiles for insert to authenticated
with check (
    user_id = (select auth.uid())
    and role = 'member'
    and organization_id is null
);

-- Solo administradores pueden cambiar perfiles de su organización
drop policy if exists "profiles_update_admin" on public.profiles;
create policy "profiles_update_admin"
on public.profiles for update to authenticated
using (public.is_org_admin(organization_id))
with check (public.is_org_admin(organization_id));

-- Expedientes: miembros de la organización pueden consultar
drop policy if exists "cases_read_org" on public.cases;
create policy "cases_read_org"
on public.cases for select to authenticated
using (public.is_org_member(organization_id));

drop policy if exists "cases_insert_org" on public.cases;
create policy "cases_insert_org"
on public.cases for insert to authenticated
with check (
    public.is_org_member(organization_id)
    and created_by = (select auth.uid())
);

drop policy if exists "cases_update_org" on public.cases;
create policy "cases_update_org"
on public.cases for update to authenticated
using (public.is_org_member(organization_id))
with check (public.is_org_member(organization_id));

drop policy if exists "cases_delete_admin" on public.cases;
create policy "cases_delete_admin"
on public.cases for delete to authenticated
using (public.is_org_admin(organization_id));

-- Tareas: acceso limitado a la organización
drop policy if exists "tasks_read_org" on public.case_tasks;
create policy "tasks_read_org"
on public.case_tasks for select to authenticated
using (public.is_org_member(organization_id));

drop policy if exists "tasks_insert_org" on public.case_tasks;
create policy "tasks_insert_org"
on public.case_tasks for insert to authenticated
with check (
    public.is_org_member(organization_id)
    and exists (
        select 1 from public.cases c
        where c.id = case_id
          and c.organization_id = organization_id
    )
);

drop policy if exists "tasks_update_org" on public.case_tasks;
create policy "tasks_update_org"
on public.case_tasks for update to authenticated
using (public.is_org_member(organization_id))
with check (public.is_org_member(organization_id));

drop policy if exists "tasks_delete_admin" on public.case_tasks;
create policy "tasks_delete_admin"
on public.case_tasks for delete to authenticated
using (public.is_org_admin(organization_id));

-- Historial: miembros pueden consultar y registrar eventos
drop policy if exists "history_read_org" on public.case_history;
create policy "history_read_org"
on public.case_history for select to authenticated
using (public.is_org_member(organization_id));

drop policy if exists "history_insert_org" on public.case_history;
create policy "history_insert_org"
on public.case_history for insert to authenticated
with check (
    public.is_org_member(organization_id)
    and user_id = (select auth.uid())
);

-- Índices
create index if not exists profiles_org_idx
    on public.profiles(organization_id);
create index if not exists cases_org_idx
    on public.cases(organization_id);
create index if not exists tasks_case_idx
    on public.case_tasks(case_id);
create index if not exists tasks_assigned_idx
    on public.case_tasks(assigned_to);
create index if not exists history_case_idx
    on public.case_history(case_id);

commit;
