
create policy "admins insert roles" on public.user_roles for insert to authenticated
  with check (public.has_role(auth.uid(), 'admin'));
create policy "admins delete roles" on public.user_roles for delete to authenticated
  using (public.has_role(auth.uid(), 'admin'));
