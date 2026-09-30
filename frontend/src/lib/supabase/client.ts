import { createBrowserClient } from "@supabase/ssr";
import { hasSupabasePublicConfig } from "@/lib/supabase/config";

export function createClient() {
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const supabasePublishableKey =
    process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY;

  if (!supabaseUrl || !supabasePublishableKey || !hasSupabasePublicConfig()) {
    throw new Error("Supabase public environment variables are not configured.");
  }

  return createBrowserClient(supabaseUrl, supabasePublishableKey);
}
