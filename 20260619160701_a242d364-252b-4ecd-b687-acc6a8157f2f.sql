
create policy "public read product images"
on storage.objects for select to anon, authenticated
using (bucket_id = 'product-images');

create policy "admins upload product images"
on storage.objects for insert to authenticated
with check (bucket_id = 'product-images' and public.has_role(auth.uid(), 'admin'));

create policy "admins update product images"
on storage.objects for update to authenticated
using (bucket_id = 'product-images' and public.has_role(auth.uid(), 'admin'));

create policy "admins delete product images"
on storage.objects for delete to authenticated
using (bucket_id = 'product-images' and public.has_role(auth.uid(), 'admin'));
