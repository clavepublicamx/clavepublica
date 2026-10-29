
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const SUPABASE_URL = "https://wduengxwzwznndvbyrfq.supabase.co";
const SUPABASE_KEY = "sb_publishable_UQqCwe920bgAgI5mMdxEbg_Zhfq1kMN";

export const supabase = createClient(SUPABASE_URL, SUPABASE_KEY, {
  auth: {
    persistSession: true,
    autoRefreshToken: true,
    detectSessionInUrl: true
  }
});

window.supabase = supabase;
window.dispatchEvent(new Event("supabase-ready"));
