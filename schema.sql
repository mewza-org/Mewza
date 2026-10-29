-- Mewza database. Supabase dashboard -> SQL Editor -> New query -> paste all of this -> Run.

create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text unique not null check (username ~ '^[A-Za-z0-9_]{3,20}$'),
  is_admin boolean not null default false
);
create table public.repos (
  id uuid primary key default gen_random_uuid(),
  owner uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  name text not null check (name ~ '^[A-Za-z0-9._-]{2,40}$'),
  description text check (char_length(description) <= 280),
  language text check (char_length(language) <= 30),
  url text check (char_length(url) <= 300),
  is_private boolean not null default false,
  created_at timestamptz not null default now()
);
create table public.favorites (
  user_id uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  repo_id uuid not null references public.repos(id) on delete cascade,
  primary key (user_id, repo_id)
);
create table public.replies (
  id uuid primary key default gen_random_uuid(),
  repo_id uuid not null references public.repos(id) on delete cascade,
  author uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  body text not null check (char_length(body) between 1 and 500),
  created_at timestamptz not null default now()
);

-- Who is an admin (used by the rules below)
create function public.is_admin() returns boolean
language sql security definer set search_path = public stable as $$
  select coalesce((select is_admin from public.profiles where id = auth.uid()), false)
$$;

-- Every new sign-up gets a profile with the username they picked
create function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, username) values (new.id, new.raw_user_meta_data->>'username');
  return new;
end $$;
create trigger on_auth_user_created after insert on auth.users
for each row execute function public.handle_new_user();

-- Rules: who can read and write what
alter table public.profiles  enable row level security;
alter table public.repos     enable row level security;
alter table public.favorites enable row level security;
alter table public.replies   enable row level security;

-- profiles: everyone can read usernames; nobody can edit (so nobody can make themselves admin)
create policy "profiles readable" on public.profiles for select using (true);

-- repos: public ones for everyone, private ones for admins only.
-- Anyone logged in can add a public repo, only admins can add a private one.
-- Owners can remove their own repos, admins can remove any.
create policy "repos read"   on public.repos for select using (not is_private or public.is_admin());
create policy "repos add"    on public.repos for insert with check (owner = auth.uid() and (not is_private or public.is_admin()));
create policy "repos remove" on public.repos for delete using (owner = auth.uid() or public.is_admin());

-- favourites: everyone can count them, you only add and remove your own
create policy "favs read"   on public.favorites for select using (exists (select 1 from public.repos r where r.id = repo_id));
create policy "favs add"    on public.favorites for insert with check (user_id = auth.uid() and exists (select 1 from public.repos r where r.id = repo_id));
create policy "favs remove" on public.favorites for delete using (user_id = auth.uid());

-- replies: everyone reads, logged-in people reply, authors and admins delete
create policy "replies read"   on public.replies for select using (exists (select 1 from public.repos r where r.id = repo_id));
create policy "replies add"    on public.replies for insert with check (author = auth.uid() and exists (select 1 from public.repos r where r.id = repo_id));
create policy "replies remove" on public.replies for delete using (author = auth.uid() or public.is_admin());

-- AFTER you have created your own account on the site, make yourself admin.
-- Replace abiilityjoy with the username you signed up with, then run this line alone:
-- update public.profiles set is_admin = true where username = 'abiilityjoy';
