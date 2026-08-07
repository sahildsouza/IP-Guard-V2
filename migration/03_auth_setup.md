# Auth setup for the new Supabase project

Do these in your Supabase dashboard after running `01_schema.sql`.

## 1. Email + password

Authentication → Sign In / Providers → **Email**

- Enable email provider: ON
- Confirm email: ON (recommended). If you want frictionless testing, turn it off
  temporarily — do not ship with it off.
- Enable "Prevent use of leaked passwords" (HIBP) — recommended.

## 2. Anonymous sign-ins

Authentication → Sign In / Providers → **Anonymous sign-ins: OFF**.
The app has no anonymous flow and leaving this on creates unowned rows.

## 3. Google sign-in

Authentication → Sign In / Providers → **Google** → enable.

You need a Google OAuth client:

1. Google Cloud Console → APIs & Services → Credentials → Create credentials →
   OAuth client ID → Web application.
2. Authorized redirect URI — copy the callback URL Supabase shows on the Google
   provider page. It looks like:
   `https://<your-project-ref>.supabase.co/auth/v1/callback`
3. Paste the resulting **Client ID** and **Client secret** into the Supabase
   Google provider form and save.

## 4. URL configuration

Authentication → URL Configuration

- **Site URL**: your published app URL (e.g. `https://your-app.lovable.app`)
- **Redirect URLs**: add every origin the app runs on, including the Lovable
  preview URL and `http://localhost:8080` for local work. Without these, Google
  sign-in and email confirmation links bounce users back to the wrong place.

## 5. Code change required in the new project

This project signs in with Google through the Lovable Cloud broker:

```ts
import { lovable } from "@/integrations/lovable";
await lovable.auth.signInWithOAuth("google", { redirect_uri: window.location.origin });
```

On your own Supabase project that broker does not exist. In `src/routes/auth.tsx`
the Google button becomes:

```ts
import { supabase } from "@/integrations/supabase/client";
await supabase.auth.signInWithOAuth({
  provider: "google",
  options: { redirectTo: window.location.origin },
});
```

Ask me to make this change once you're in the new project — it's a one-line swap
plus dropping the `@/integrations/lovable` import.
