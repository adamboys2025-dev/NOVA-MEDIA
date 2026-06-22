
-- Roles enum
create type public.app_role as enum ('admin', 'user');

-- Profiles
create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text,
  display_name text,
  created_at timestamptz not null default now()
);
grant select, insert, update on public.profiles to authenticated;
grant all on public.profiles to service_role;
alter table public.profiles enable row level security;
create policy "profiles readable by everyone authenticated" on public.profiles for select to authenticated using (true);
create policy "users update own profile" on public.profiles for update to authenticated using (auth.uid() = id) with check (auth.uid() = id);
create policy "users insert own profile" on public.profiles for insert to authenticated with check (auth.uid() = id);

-- User roles
create table public.user_roles (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  role public.app_role not null,
  unique(user_id, role)
);
grant select on public.user_roles to authenticated;
grant all on public.user_roles to service_role;
alter table public.user_roles enable row level security;
create policy "users read own roles" on public.user_roles for select to authenticated using (auth.uid() = user_id);

-- has_role function
create or replace function public.has_role(_user_id uuid, _role public.app_role)
returns boolean
language sql stable security definer set search_path = public
as $$
  select exists (select 1 from public.user_roles where user_id = _user_id and role = _role)
$$;

-- Admin can read all roles
create policy "admins read all roles" on public.user_roles for select to authenticated using (public.has_role(auth.uid(), 'admin'));

-- Pending admin invites (by email)
create table public.admin_invites (
  id uuid primary key default gen_random_uuid(),
  email text not null unique,
  invited_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  consumed_at timestamptz
);
grant select, insert, update, delete on public.admin_invites to authenticated;
grant all on public.admin_invites to service_role;
alter table public.admin_invites enable row level security;
create policy "admins manage invites" on public.admin_invites for all to authenticated
  using (public.has_role(auth.uid(), 'admin')) with check (public.has_role(auth.uid(), 'admin'));

-- Seed first admin invite
insert into public.admin_invites (email) values ('nadorigaming06@gmail.com') on conflict do nothing;

-- Products
create table public.products (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  description text,
  price numeric(10,2) not null default 0,
  stock int not null default 0,
  image_url text,
  category text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
grant select on public.products to anon, authenticated;
grant insert, update, delete on public.products to authenticated;
grant all on public.products to service_role;
alter table public.products enable row level security;
create policy "anyone can view products" on public.products for select to anon, authenticated using (true);
create policy "admins insert products" on public.products for insert to authenticated with check (public.has_role(auth.uid(), 'admin'));
create policy "admins update products" on public.products for update to authenticated using (public.has_role(auth.uid(), 'admin')) with check (public.has_role(auth.uid(), 'admin'));
create policy "admins delete products" on public.products for delete to authenticated using (public.has_role(auth.uid(), 'admin'));

-- Login logs
create table public.login_logs (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete set null,
  email text,
  display_name text,
  provider text,
  created_at timestamptz not null default now()
);
grant insert on public.login_logs to authenticated;
grant select on public.login_logs to authenticated;
grant all on public.login_logs to service_role;
alter table public.login_logs enable row level security;
create policy "users insert own login log" on public.login_logs for insert to authenticated with check (auth.uid() = user_id);
create policy "admins read login logs" on public.login_logs for select to authenticated using (public.has_role(auth.uid(), 'admin'));

-- Store settings
create table public.store_settings (
  id int primary key default 1,
  whatsapp_number text not null default '0712743851',
  currency text not null default 'MAD',
  store_name text not null default 'ADAM SHOP',
  updated_at timestamptz not null default now(),
  constraint single_row check (id = 1)
);
grant select on public.store_settings to anon, authenticated;
grant insert, update on public.store_settings to authenticated;
grant all on public.store_settings to service_role;
alter table public.store_settings enable row level security;
create policy "anyone reads settings" on public.store_settings for select to anon, authenticated using (true);
create policy "admins update settings" on public.store_settings for update to authenticated using (public.has_role(auth.uid(), 'admin')) with check (public.has_role(auth.uid(), 'admin'));
create policy "admins insert settings" on public.store_settings for insert to authenticated with check (public.has_role(auth.uid(), 'admin'));
insert into public.store_settings (id) values (1) on conflict do nothing;

-- Trigger: on new user, create profile + consume admin invite if email matches
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public
as $$
begin
  insert into public.profiles (id, email, display_name)
  values (new.id, new.email, coalesce(new.raw_user_meta_data->>'full_name', new.raw_user_meta_data->>'name', new.email))
  on conflict (id) do nothing;

  -- If email is in admin_invites, grant admin
  if exists (select 1 from public.admin_invites where lower(email) = lower(new.email) and consumed_at is null) then
    insert into public.user_roles (user_id, role) values (new.id, 'admin') on conflict do nothing;
    update public.admin_invites set consumed_at = now() where lower(email) = lower(new.email);
  else
    insert into public.user_roles (user_id, role) values (new.id, 'user') on conflict do nothing;
  end if;

  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- updated_at trigger for products
create or replace function public.touch_updated_at()
returns trigger language plpgsql as $$
begin new.updated_at = now(); return new; end;
$$;
create trigger products_updated_at before update on public.products
  for each row execute function public.touch_updated_at();

-- Enable realtime
alter publication supabase_realtime add table public.products;
alter publication supabase_realtime add table public.store_settings;
