-- IP-Guard — storage rules for bulk Excel uploads
--
-- PREREQUISITE (do this in the dashboard, not here):
--   Storage -> New bucket
--     Name:   bulk-uploads
--     Public: OFF  (private)
--
-- Then run this file in the SQL editor.
--
-- Path convention the app uses: <auth.uid()>/<filename>.xlsx
-- The first path segment is the owner's user id, which is what these
-- policies check, so users can only ever touch their own uploads.

create policy "bulk_uploads_own_insert"
  on storage.objects for insert
  to authenticated
  with check (
    bucket_id = 'bulk-uploads'
    and (auth.uid())::text = (storage.foldername(name))[1]
  );

create policy "bulk_uploads_own_select"
  on storage.objects for select
  to authenticated
  using (
    bucket_id = 'bulk-uploads'
    and (auth.uid())::text = (storage.foldername(name))[1]
  );

create policy "bulk_uploads_own_delete"
  on storage.objects for delete
  to authenticated
  using (
    bucket_id = 'bulk-uploads'
    and (auth.uid())::text = (storage.foldername(name))[1]
  );
