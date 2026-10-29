-- ScamCheck Hub: least-privilege browser access.
-- Private account, subscription, and audit data are blocked from browser roles.
REVOKE ALL PRIVILEGES ON TABLE public.profiles, public.scam_reports, public.checks, public.subscriptions, public.audit_logs FROM anon, authenticated;

GRANT INSERT (user_id, input_type, input_hash, risk_score, risk_level, result, image_hash) ON public.checks TO anon, authenticated;
GRANT SELECT (id, user_id, input_type, input_hash, risk_score, risk_level, result, image_hash, created_at) ON public.checks TO authenticated;

DROP POLICY IF EXISTS "Anonymous visitors can save checks" ON public.checks;
DROP POLICY IF EXISTS "Users can save own checks" ON public.checks;
DROP POLICY IF EXISTS "Users can view own checks" ON public.checks;
CREATE POLICY "Anonymous visitors can save checks" ON public.checks
  FOR INSERT TO anon WITH CHECK (user_id IS NULL);
CREATE POLICY "Users can save own checks" ON public.checks
  FOR INSERT TO authenticated WITH CHECK (user_id = (select auth.uid()));
CREATE POLICY "Users can view own checks" ON public.checks
  FOR SELECT TO authenticated USING (user_id = (select auth.uid()));

DROP POLICY IF EXISTS "Anyone can submit scam reports" ON public.scam_reports;
DROP POLICY IF EXISTS "Anyone can view approved scam reports" ON public.scam_reports;
DROP POLICY IF EXISTS "Public can submit pending scam reports" ON public.scam_reports;
DROP POLICY IF EXISTS "Public can read published scam reports" ON public.scam_reports;
DROP POLICY IF EXISTS "Users can submit own scam reports" ON public.scam_reports;
DROP POLICY IF EXISTS "Users can read own scam reports" ON public.scam_reports;
DROP POLICY IF EXISTS "Public and owners can read visible scam reports" ON public.scam_reports;

CREATE POLICY "Public can submit pending scam reports" ON public.scam_reports
  FOR INSERT TO anon WITH CHECK (status = 'pending' AND reporter_id IS NULL);
CREATE POLICY "Users can submit own scam reports" ON public.scam_reports
  FOR INSERT TO authenticated WITH CHECK (status = 'pending' AND reporter_id = (select auth.uid()));
CREATE POLICY "Public and owners can read visible scam reports" ON public.scam_reports
  FOR SELECT TO anon, authenticated USING (status = 'approved' OR (select auth.uid()) = reporter_id);

GRANT INSERT (title, target, description) ON public.scam_reports TO anon;
GRANT INSERT (reporter_id, title, target, description) ON public.scam_reports TO authenticated;
GRANT SELECT (id, title, target, description, created_at, status) ON public.scam_reports TO anon, authenticated;

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['profiles','subscriptions','audit_logs'] LOOP
    EXECUTE format('DROP POLICY IF EXISTS "No browser access by default" ON public.%I', t);
    EXECUTE format('CREATE POLICY "No browser access by default" ON public.%I FOR ALL TO anon, authenticated USING (false) WITH CHECK (false)', t);
  END LOOP;
END $$;
