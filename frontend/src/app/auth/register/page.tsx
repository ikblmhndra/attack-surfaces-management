"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Shield, Eye, EyeOff, Loader2, AlertCircle, Lock, Mail, User, Building2, Crosshair, Check } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import { authAPI, tokenStorage } from "@/lib/api";
import { useWorkspaceStore } from "@/store/workspace";
import { cn } from "@/lib/utils";

const registerSchema = z.object({
  full_name: z.string().min(1, "Full name is required"),
  email: z.string().email("Invalid email address"),
  workspace_name: z.string().min(1, "Workspace name is required"),
  password: z.string().min(12, "Password must be at least 12 characters"),
  enabled_products: z.array(z.enum(["asm", "bounty"])).min(1, "Choose at least one product"),
});

type RegisterForm = z.infer<typeof registerSchema>;

const PRODUCTS = [
  {
    value: "asm" as const,
    icon: Shield,
    name: "Attack Surface Management",
    description: "Continuous discovery, scanning, and risk scoring for your infrastructure.",
    accent: "brand" as const,
  },
  {
    value: "bounty" as const,
    icon: Crosshair,
    name: "Bug Bounty",
    description: "Authorized, scope-gated active testing for bug bounty engagements.",
    accent: "rose" as const,
  },
];

export default function RegisterPage() {
  const router = useRouter();
  const { login } = useWorkspaceStore();
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const form = useForm<RegisterForm>({
    resolver: zodResolver(registerSchema),
    defaultValues: { full_name: "", email: "", workspace_name: "", password: "", enabled_products: ["asm"] },
  });

  const selectedProducts = form.watch("enabled_products");
  const toggleProduct = (value: "asm" | "bounty") => {
    const current = form.getValues("enabled_products");
    const next = current.includes(value)
      ? current.filter((p) => p !== value)
      : [...current, value];
    form.setValue("enabled_products", next, { shouldValidate: true });
  };

  const onSubmit = async (data: RegisterForm) => {
    setIsLoading(true);
    setError(null);

    try {
      const response = await authAPI.register({
        email: data.email,
        password: data.password,
        full_name: data.full_name,
        workspace_name: data.workspace_name,
        enabled_products: data.enabled_products,
      });
      const { access_token, refresh_token, user_id, workspace_id, role } = response.data;

      tokenStorage.setTokens(access_token, refresh_token);
      const meResp = await authAPI.me();

      login(access_token, refresh_token, meResp.data);
      const products: string[] = meResp.data.enabled_products || ["asm"];
      router.push(products.includes("asm") ? "/dashboard" : "/dashboard/bounty");
    } catch (err: any) {
      const status = err.response?.status;
      const detail = err.response?.data?.detail;

      if (status === 409) {
        setError("An account with this email already exists");
      } else if (status === 422) {
        setError(detail?.map((d: any) => d.msg).join(", ") || "Invalid input");
      } else {
        setError(detail || "Registration failed. Please try again.");
      }
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
            Create your workspace
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

            {/* Full Name */}
            <div>
              <label className="block text-sm font-medium text-foreground mb-1.5">
                Full name
              </label>
              <div className="relative">
                <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <input
                  {...form.register("full_name")}
                  type="text"
                  autoComplete="name"
                  autoFocus
                  placeholder="John Doe"
                  className={cn(
                    "w-full pl-10 pr-4 py-2.5 bg-surface-800 border rounded-lg text-foreground",
                    "placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-brand-500",
                    form.formState.errors.full_name ? "border-red-500" : "border-border",
                  )}
                />
              </div>
              {form.formState.errors.full_name && (
                <p className="text-xs text-red-400 mt-1">{form.formState.errors.full_name.message}</p>
              )}
            </div>

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

            {/* Workspace Name */}
            <div>
              <label className="block text-sm font-medium text-foreground mb-1.5">
                Workspace name
              </label>
              <div className="relative">
                <Building2 className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <input
                  {...form.register("workspace_name")}
                  type="text"
                  autoComplete="organization"
                  placeholder="My Company"
                  className={cn(
                    "w-full pl-10 pr-4 py-2.5 bg-surface-800 border rounded-lg text-foreground",
                    "placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-brand-500",
                    form.formState.errors.workspace_name ? "border-red-500" : "border-border",
                  )}
                />
              </div>
              {form.formState.errors.workspace_name && (
                <p className="text-xs text-red-400 mt-1">{form.formState.errors.workspace_name.message}</p>
              )}
            </div>

            {/* Products */}
            <div>
              <label className="block text-sm font-medium text-foreground mb-1.5">
                What do you want to use this workspace for?
              </label>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                {PRODUCTS.map((product) => {
                  const selected = selectedProducts?.includes(product.value);
                  const isRose = product.accent === "rose";
                  return (
                    <button
                      key={product.value}
                      type="button"
                      onClick={() => toggleProduct(product.value)}
                      aria-pressed={selected}
                      className={cn(
                        "relative text-left p-3.5 rounded-lg border transition-colors",
                        selected
                          ? isRose
                            ? "border-rose-500/50 bg-rose-500/10"
                            : "border-brand-500/50 bg-brand-500/10"
                          : "border-border bg-surface-800 hover:bg-surface-700/50",
                      )}
                    >
                      <div className="flex items-start gap-2.5">
                        <product.icon className={cn(
                          "w-4 h-4 flex-shrink-0 mt-0.5",
                          selected ? (isRose ? "text-rose-400" : "text-brand-400") : "text-muted-foreground",
                        )} />
                        <div className="min-w-0">
                          <p className="text-sm font-medium text-foreground">{product.name}</p>
                          <p className="text-xs text-muted-foreground mt-0.5">{product.description}</p>
                        </div>
                      </div>
                      {selected && (
                        <div className={cn(
                          "absolute top-3 right-3 w-4 h-4 rounded-full flex items-center justify-center",
                          isRose ? "bg-rose-500" : "bg-brand-500",
                        )}>
                          <Check className="w-2.5 h-2.5 text-white" strokeWidth={3} />
                        </div>
                      )}
                    </button>
                  );
                })}
              </div>
              {form.formState.errors.enabled_products && (
                <p className="text-xs text-red-400 mt-1.5">{form.formState.errors.enabled_products.message}</p>
              )}
              <p className="text-xs text-muted-foreground mt-1.5">
                Select one or both. This can&apos;t be changed after your workspace is created.
              </p>
            </div>

            {/* Password */}
            <div>
              <label className="block text-sm font-medium text-foreground mb-1.5">
                Password
              </label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <input
                  {...form.register("password")}
                  type={showPassword ? "text" : "password"}
                  autoComplete="new-password"
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
              <p className="text-xs text-muted-foreground mt-1">
                At least 12 characters
              </p>
            </div>

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
                  Creating workspace...
                </span>
              ) : (
                "Create workspace"
              )}
            </button>
          </form>

          <p className="text-center text-sm text-muted-foreground mt-6">
            Already have an account?{" "}
            <a href="/auth/login" className="text-brand-400 hover:text-brand-300 font-medium">
              Sign in
            </a>
          </p>
        </div>

        {/* Footer */}
        <p className="text-center text-xs text-muted-foreground mt-6">
          ASM Platform v1.0 · For authorized security assessments only
        </p>
      </motion.div>
    </div>
  );
}
