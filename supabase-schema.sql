-- HELPATT secure Supabase schema
create table if not exists public.profiles (
 id uuid primary key references auth.users(id) on delete cascade,
 display_name text not null default 'Ученик',
 role text not null default 'student' check (role in ('student','creator')),
 created_at timestamptz not null default now()
);
create table if not exists public.attempts (
 id uuid primary key default gen_random_uuid(),
 user_id uuid not null references auth.users(id) on delete cascade,
 mode text not null, score int not null, total int not null, percent int not null,
 answers jsonb not null default '[]'::jsonb,
 created_at timestamptz not null default now()
);
alter table public.profiles enable row level security;
alter table public.attempts enable row level security;
revoke all on public.profiles from anon, authenticated;
revoke all on public.attempts from anon, authenticated;
grant select on public.profiles to authenticated;
grant select, insert on public.attempts to authenticated;
create policy "profile_self_read" on public.profiles for select to authenticated using (id=(select auth.uid()));
create policy "attempt_self_read" on public.attempts for select to authenticated using (user_id=(select auth.uid()));
create policy "attempt_self_insert" on public.attempts for insert to authenticated with check (user_id=(select auth.uid()));
create or replace function public.handle_new_user() returns trigger language plpgsql security definer set search_path='' as $$
begin insert into public.profiles(id,display_name) values(new.id,coalesce(new.raw_user_meta_data->>'display_name','Ученик')); return new; end $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users for each row execute procedure public.handle_new_user();

-- Creator-only view. RLS on source tables still applies, so use a security-invoker view plus creator SELECT policies.
create or replace function public.is_creator() returns boolean language sql stable security definer set search_path='' as $$
 select exists(select 1 from public.profiles p where p.id=(select auth.uid()) and p.role='creator') $$;
revoke all on function public.is_creator() from public;
grant execute on function public.is_creator() to authenticated;
create policy "creator_profiles_read" on public.profiles for select to authenticated using (public.is_creator());
create policy "creator_attempts_read" on public.attempts for select to authenticated using (public.is_creator());
create or replace view public.creator_attempts with (security_invoker=true) as
 select a.*,p.display_name,u.email from public.attempts a join public.profiles p on p.id=a.user_id join auth.users u on u.id=a.user_id;
revoke all on public.creator_attempts from anon;
grant select on public.creator_attempts to authenticated;

-- IMPORTANT: after registering your own account, run ONCE in Supabase SQL editor:
-- update public.profiles set role='creator' where id=(select id from auth.users where email='YOUR_EMAIL' limit 1);
