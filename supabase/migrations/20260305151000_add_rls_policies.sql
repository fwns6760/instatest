-- 003: RLS policies for MVP access controls

create or replace function public.current_user_is_active()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select coalesce(
    (select not p.is_suspended from public.profiles p where p.id = auth.uid()),
    true
  );
$$;

create or replace function public.current_user_is_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select coalesce(
    (select p.is_admin from public.profiles p where p.id = auth.uid()),
    false
  );
$$;

create or replace function public.current_user_is_poster()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select coalesce(
    (select p.is_poster from public.profiles p where p.id = auth.uid()),
    false
  );
$$;

grant execute on function public.current_user_is_active() to authenticated;
grant execute on function public.current_user_is_admin() to authenticated;
grant execute on function public.current_user_is_poster() to authenticated;

alter table public.profiles enable row level security;
alter table public.posts enable row level security;
alter table public.tags enable row level security;
alter table public.post_tags enable row level security;
alter table public.follows enable row level security;
alter table public.likes enable row level security;
alter table public.comments enable row level security;

drop policy if exists profiles_select_active on public.profiles;
create policy profiles_select_active
  on public.profiles
  for select
  to authenticated
  using (
    auth.uid() is not null
    and public.current_user_is_active()
  );

drop policy if exists profiles_insert_self on public.profiles;
create policy profiles_insert_self
  on public.profiles
  for insert
  to authenticated
  with check (
    auth.uid() is not null
    and auth.uid() = id
  );

drop policy if exists profiles_update_self_or_admin on public.profiles;
create policy profiles_update_self_or_admin
  on public.profiles
  for update
  to authenticated
  using (
    auth.uid() is not null
    and public.current_user_is_active()
    and (id = auth.uid() or public.current_user_is_admin())
  )
  with check (
    auth.uid() is not null
    and public.current_user_is_active()
    and (id = auth.uid() or public.current_user_is_admin())
  );

drop policy if exists profiles_delete_admin on public.profiles;
create policy profiles_delete_admin
  on public.profiles
  for delete
  to authenticated
  using (
    auth.uid() is not null
    and public.current_user_is_active()
    and public.current_user_is_admin()
  );

drop policy if exists posts_select_visible on public.posts;
create policy posts_select_visible
  on public.posts
  for select
  to authenticated
  using (
    auth.uid() is not null
    and public.current_user_is_active()
    and (
      visibility = 'public'
      or user_id = auth.uid()
      or public.current_user_is_admin()
    )
  );

drop policy if exists posts_insert_poster_only on public.posts;
create policy posts_insert_poster_only
  on public.posts
  for insert
  to authenticated
  with check (
    auth.uid() is not null
    and public.current_user_is_active()
    and user_id = auth.uid()
    and (public.current_user_is_poster() or public.current_user_is_admin())
  );

drop policy if exists posts_update_owner_or_admin on public.posts;
create policy posts_update_owner_or_admin
  on public.posts
  for update
  to authenticated
  using (
    auth.uid() is not null
    and public.current_user_is_active()
    and (user_id = auth.uid() or public.current_user_is_admin())
  )
  with check (
    auth.uid() is not null
    and public.current_user_is_active()
    and (user_id = auth.uid() or public.current_user_is_admin())
  );

drop policy if exists posts_delete_owner_or_admin on public.posts;
create policy posts_delete_owner_or_admin
  on public.posts
  for delete
  to authenticated
  using (
    auth.uid() is not null
    and public.current_user_is_active()
    and (user_id = auth.uid() or public.current_user_is_admin())
  );

drop policy if exists tags_select_active on public.tags;
create policy tags_select_active
  on public.tags
  for select
  to authenticated
  using (
    auth.uid() is not null
    and public.current_user_is_active()
  );

drop policy if exists tags_write_poster_or_admin on public.tags;
create policy tags_write_poster_or_admin
  on public.tags
  for all
  to authenticated
  using (
    auth.uid() is not null
    and public.current_user_is_active()
    and (public.current_user_is_poster() or public.current_user_is_admin())
  )
  with check (
    auth.uid() is not null
    and public.current_user_is_active()
    and (public.current_user_is_poster() or public.current_user_is_admin())
  );

drop policy if exists post_tags_select_active on public.post_tags;
create policy post_tags_select_active
  on public.post_tags
  for select
  to authenticated
  using (
    auth.uid() is not null
    and public.current_user_is_active()
  );

drop policy if exists post_tags_insert_owner_or_admin on public.post_tags;
create policy post_tags_insert_owner_or_admin
  on public.post_tags
  for insert
  to authenticated
  with check (
    auth.uid() is not null
    and public.current_user_is_active()
    and (
      public.current_user_is_admin()
      or exists (
        select 1
        from public.posts p
        where p.id = post_id
          and p.user_id = auth.uid()
      )
    )
  );

drop policy if exists post_tags_delete_owner_or_admin on public.post_tags;
create policy post_tags_delete_owner_or_admin
  on public.post_tags
  for delete
  to authenticated
  using (
    auth.uid() is not null
    and public.current_user_is_active()
    and (
      public.current_user_is_admin()
      or exists (
        select 1
        from public.posts p
        where p.id = post_id
          and p.user_id = auth.uid()
      )
    )
  );

drop policy if exists follows_select_active on public.follows;
create policy follows_select_active
  on public.follows
  for select
  to authenticated
  using (
    auth.uid() is not null
    and public.current_user_is_active()
  );

drop policy if exists follows_insert_self on public.follows;
create policy follows_insert_self
  on public.follows
  for insert
  to authenticated
  with check (
    auth.uid() is not null
    and public.current_user_is_active()
    and follower_id = auth.uid()
  );

drop policy if exists follows_delete_self on public.follows;
create policy follows_delete_self
  on public.follows
  for delete
  to authenticated
  using (
    auth.uid() is not null
    and public.current_user_is_active()
    and follower_id = auth.uid()
  );

drop policy if exists likes_select_active on public.likes;
create policy likes_select_active
  on public.likes
  for select
  to authenticated
  using (
    auth.uid() is not null
    and public.current_user_is_active()
  );

drop policy if exists likes_insert_self on public.likes;
create policy likes_insert_self
  on public.likes
  for insert
  to authenticated
  with check (
    auth.uid() is not null
    and public.current_user_is_active()
    and user_id = auth.uid()
  );

drop policy if exists likes_delete_self on public.likes;
create policy likes_delete_self
  on public.likes
  for delete
  to authenticated
  using (
    auth.uid() is not null
    and public.current_user_is_active()
    and user_id = auth.uid()
  );

drop policy if exists comments_select_active on public.comments;
create policy comments_select_active
  on public.comments
  for select
  to authenticated
  using (
    auth.uid() is not null
    and public.current_user_is_active()
  );

drop policy if exists comments_insert_self on public.comments;
create policy comments_insert_self
  on public.comments
  for insert
  to authenticated
  with check (
    auth.uid() is not null
    and public.current_user_is_active()
    and user_id = auth.uid()
  );

drop policy if exists comments_delete_owner_author_or_admin on public.comments;
create policy comments_delete_owner_author_or_admin
  on public.comments
  for delete
  to authenticated
  using (
    auth.uid() is not null
    and public.current_user_is_active()
    and (
      user_id = auth.uid()
      or public.current_user_is_admin()
      or exists (
        select 1
        from public.posts p
        where p.id = comments.post_id
          and p.user_id = auth.uid()
      )
    )
  );
