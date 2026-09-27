export function hasSupabasePublicConfig() {
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const publishableKey = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY;

  return Boolean(
    supabaseUrl &&
      publishableKey &&
      !publishableKey.endsWith("replace_me"),
  );
}
