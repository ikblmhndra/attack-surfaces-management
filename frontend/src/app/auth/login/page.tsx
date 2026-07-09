"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Shield, Eye, EyeOff, Loader2, AlertCircle, Lock, Mail } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import { authAPI, tokenStorage } from "@/lib/api";
import { useWorkspaceStore } from "@/store/workspace";
import { cn } from "@/lib/utils";

const loginSchema = z.object({
  email: z.string().email("Invalid email address"),
  password: z.string().min(1, "Password is required"),
  mfa_code: z.string().optional(),
});

type LoginForm = z.infer<typeof loginSchema>;

export default function LoginPage() {
  const router = useRouter();
  const { login } = useWorkspaceStore();
  const [showPassword, setShowPassword] = useState(false);
  const [mfaRequired, setMfaRequired] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const form = useForm<LoginForm>({
    resolver: zodResolver(loginSchema),
    defaultValues: { email: "", password: "", mfa_code: "" },
  });

  const onSubmit = async (data: LoginForm) => {
    setIsLoading(true);
    setError(null);

    try {
      const response = await authAPI.login(data.email, data.password, data.mfa_code);
      const { access_token, refresh_token, user_id, workspace_id, role } = response.data;

      // Fetch user profile
      tokenStorage.setTokens(access_token, refresh_token);
      const meResp = await authAPI.me();

      login(access_token, refresh_token, meResp.data);
      router.push("/dashboard");
    } catch (err: any) {
      const status = err.response?.status;
      const detail = err.response?.data?.detail;

      if (status === 428 || err.response?.headers?.["x-mfa-required"]) {
        setMfaRequired(true);
        setError("Please enter your MFA code");
        setIsLoading(false);
        return;
      }

      setError(
        status === 401 ? "Invalid email or password" :
        status === 403 ? "Account is disabled" :
        status === 429 ? "Too many attempts. Try again later." :
        detail || "Login failed. Please try again."
      );
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-surface-950 flex items-center justify-center p-4 relative overflow-hidden">
      {/* Background */}
      <div className="absolute inset-0 bg-hero-gradient" />
      <div
        className="absolute inset-0 opacity-30"
        style={{
          backgroundImage: "linear-gradient(rgba(14,165,233,0.05) 1px, transparent 1px), linear-gradient(90deg, rgba(14,165,233,0.05) 1px, transparent 1px)",
          backgroundSize: "40px 40px",
        }}
      />
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[600px] h-[300px] blur-3xl opacity-20"
        style={{ background: "radial-gradient(circle, #0ea5e9, transparent)" }}
      />

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
        className="w-full max-w-md relative z-10"
      >
        {/* Logo */}
        <div className="text-center mb-8">
          <motion.div
            initial={{ scale: 0.8 }}
            animate={{ scale: 1 }}
            className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-brand-600/20 border border-brand-500/30 mb-4"
          >
            <Shield className="w-8 h-8 text-brand-400" />
          </motion.div>
          <h1 className="text-2xl font-bold text-foreground tracking-tight">ASM Platform</h1>
          <p className="text-sm text-muted-foreground mt-1">Attack Surface Management</p>
        </div>

        {/* Card */}
        <div className="glass-card p-8">
          <h2 className="text-lg font-semibold text-foreground mb-6">
            {mfaRequired ? "Two-Factor Authentication" : "Sign in to your workspace"}
          </h2>

          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-5">
            {/* Error */}
            <AnimatePresence>
              {error && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: "auto" }}
                  exit={{ opacity: 0, height: 0 }}
                  className="flex items-start gap-2.5 p-3.5 rounded-lg bg-red-500/10 border border-red-500/20"
                >
                  <AlertCircle className="w-4 h-4 text-red-400 mt-0.5 flex-shrink-0" />
                  <p className="text-sm text-red-400">{error}</p>
                </motion.div>
              )}
            </AnimatePresence>

            {/* MFA mode */}
            {mfaRequired ? (
              <div>
                <label className="block text-sm font-medium text-foreground mb-1.5">
                  Authenticator Code
                </label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                  <input
                    {...form.register("mfa_code")}
                    type="text"
                    inputMode="numeric"
                    pattern="[0-9]*"
                    maxLength={6}
                    placeholder="000000"
                    autoFocus
                    className="w-full pl-10 pr-4 py-2.5 bg-surface-800 border border-border rounded-lg
                               text-foreground text-center text-lg tracking-widest font-mono
                               placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-brand-500"
                  />
                </div>
                <p className="text-xs text-muted-foreground mt-1.5">
                  Enter the 6-digit code from your authenticator app
                </p>
              </div>
            ) : (
              <>
                {/* Email */}
                <div>
                  <label className="block text-sm font-medium text-foreground mb-1.5">
                    Email address
                  </label>
                  <div className="relative">
                    <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                    <input
                      {...form.register("email")}
                      type="email"
                      autoComplete="email"
                      autoFocus
                      placeholder="you@company.com"
                      className={cn(
                        "w-full pl-10 pr-4 py-2.5 bg-surface-800 border rounded-lg text-foreground",
                        "placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-brand-500",
                        form.formState.errors.email ? "border-red-500" : "border-border",
                      )}
                    />
                  </div>
                  {form.formState.errors.email && (
                    <p className="text-xs text-red-400 mt-1">{form.formState.errors.email.message}</p>
                  )}
                </div>

                {/* Password */}
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <label className="text-sm font-medium text-foreground">Password</label>
                    <a href="/auth/forgot-password" className="text-xs text-brand-400 hover:text-brand-300">
                      Forgot password?
                    </a>
                  </div>
                  <div className="relative">
                    <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                    <input
                      {...form.register("password")}
                      type={showPassword ? "text" : "password"}
                      autoComplete="current-password"
                      placeholder="••••••••"
                      className={cn(
                        "w-full pl-10 pr-10 py-2.5 bg-surface-800 border rounded-lg text-foreground",
                        "placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-brand-500",
                        form.formState.errors.password ? "border-red-500" : "border-border",
                      )}
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                    >
                      {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                  {form.formState.errors.password && (
                    <p className="text-xs text-red-400 mt-1">{form.formState.errors.password.message}</p>
                  )}
                </div>
              </>
            )}

            {/* Submit */}
            <button
              type="submit"
              disabled={isLoading}
              className={cn(
                "w-full py-2.5 px-4 rounded-lg font-semibold text-sm transition-all",
                "bg-brand-600 hover:bg-brand-500 text-white",
                "disabled:opacity-60 disabled:cursor-not-allowed",
                "focus:outline-none focus:ring-2 focus:ring-brand-500 focus:ring-offset-2 focus:ring-offset-surface-800",
              )}
            >
              {isLoading ? (
                <span className="flex items-center justify-center gap-2">
                  <Loader2 className="w-4 h-4 animate-spin" />
                  {mfaRequired ? "Verifying..." : "Signing in..."}
                </span>
              ) : (
                mfaRequired ? "Verify & Sign in" : "Sign in"
              )}
            </button>

            {mfaRequired && (
              <button
                type="button"
                onClick={() => { setMfaRequired(false); setError(null); }}
                className="w-full text-sm text-muted-foreground hover:text-foreground transition-colors text-center"
              >
                ← Back to login
              </button>
            )}
          </form>

          {!mfaRequired && (
            <p className="text-center text-sm text-muted-foreground mt-6">
              Don&apos;t have an account?{" "}
              <a href="/auth/register" className="text-brand-400 hover:text-brand-300 font-medium">
                Create workspace
              </a>
            </p>
          )}
        </div>

        {/* Footer */}
        <p className="text-center text-xs text-muted-foreground mt-6">
          ASM Platform v1.0 · For authorized security assessments only
        </p>
      </motion.div>
    </div>
  );
}
