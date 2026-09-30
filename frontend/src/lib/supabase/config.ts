export function hasSupabasePublicConfig() {
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const publishableKey = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY;

  return Boolean(
    supabaseUrl &&
      publishableKey &&
      !publishableKey.endsWith("replace_me") &&
      isAllowedSupabaseUrl(supabaseUrl),
  );
}

function isAllowedSupabaseUrl(value: string): boolean {
  try {
    const url = new URL(value);
    const isLocalHost = ["localhost", "127.0.0.1", "[::1]"].includes(
      url.hostname.toLowerCase(),
    );
    const localDevelopmentHttp =
      process.env.NODE_ENV !== "production" &&
      url.protocol === "http:" &&
      isLocalHost;
    return (
      !url.username &&
      !url.password &&
      !url.search &&
      !url.hash &&
      (url.protocol === "https:" || localDevelopmentHttp)
    );
  } catch {
    return false;
  }
}
