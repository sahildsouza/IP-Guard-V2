CREATE POLICY "bulk_uploads_own_select" ON storage.objects FOR SELECT TO authenticated
USING (bucket_id = 'bulk-uploads' AND auth.uid()::text = (storage.foldername(name))[1]);
CREATE POLICY "bulk_uploads_own_insert" ON storage.objects FOR INSERT TO authenticated
WITH CHECK (bucket_id = 'bulk-uploads' AND auth.uid()::text = (storage.foldername(name))[1]);
CREATE POLICY "bulk_uploads_own_delete" ON storage.objects FOR DELETE TO authenticated
USING (bucket_id = 'bulk-uploads' AND auth.uid()::text = (storage.foldername(name))[1]);