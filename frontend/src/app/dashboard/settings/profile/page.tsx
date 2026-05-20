"use client";

import { useState } from "react";
import {
  User, Mail, Shield, Save, RefreshCw, AlertTriangle, CheckCircle, Smartphone
} from "lucide-react";
import { motion } from "framer-motion";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { authAPI, apiClient } from "@/lib/api";
import { useWorkspaceStore } from "@/store/workspace";
import { cn } from "@/lib/utils";

export default function ProfilePage() {
  const { user, refreshUser } = useWorkspaceStore();
  const qc = useQueryClient();

  const [fullName, setFullName] = useState(user?.full_name || "");
  const [email] = useState(user?.email || "");
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  const [mfaSecret, setMfaSecret] = useState("");
  const [mfaQrUri, setMfaQrUri] = useState("");
  const [mfaCode, setMfaCode] = useState("");
  const [mfaStep, setMfaStep] = useState<"idle" | "setup" | "verify">("idle");

  const updateProfile = useMutation({
    mutationFn: () => apiClient.put("/auth/me", { full_name: fullName }),
    onSuccess: () => {
      toast.success("Profile updated");
      refreshUser();
    },
    onError: () => toast.error("Failed to update profile"),
  });

  const changePassword = useMutation({
    mutationFn: () =>
      apiClient.post("/auth/change-password", {
        current_password: currentPassword,
        new_password: newPassword,
      }),
    onSuccess: () => {
      toast.success("Password changed");
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
    },
    onError: () => toast.error("Failed to change password"),
  });

  const setupMFA = useMutation({
    mutationFn: () => authAPI.setupMFA(),
    onSuccess: (res) => {
      setMfaSecret(res.data.secret);
      setMfaQrUri(res.data.qr_uri || "");
      setMfaStep("verify");
    },
    onError: () => toast.error("Failed to setup MFA"),
  });

  const enableMFA = useMutation({
    mutationFn: () => authAPI.enableMFA(mfaSecret, mfaCode),
    onSuccess: () => {
      toast.success("MFA enabled");
      setMfaStep("idle");
      refreshUser();
    },
    onError: () => toast.error("Invalid code"),
  });

  return (
    <div className="p-6 space-y-6 max-w-2xl">
      <div>
        <h1 className="text-xl font-semibold text-foreground">Profile Settings</h1>
        <p className="text-sm text-muted-foreground">Manage your account details</p>
      </div>

      <div className="space-y-6">
        {/* Profile Info */}
        <div className="glass-card p-5 space-y-4">
          <h2 className="text-sm font-semibold text-foreground flex items-center gap-2">
            <User className="w-4 h-4 text-brand-400" />
            Profile Information
          </h2>
          <div className="grid gap-4">
            <div>
              <label className="block text-sm text-muted-foreground mb-1">Full Name</label>
              <input
                value={fullName}
                onChange={e => setFullName(e.target.value)}
                className="w-full px-3 py-2 bg-surface-800 border border-border rounded-lg text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-brand-500"
              />
            </div>
            <div>
              <label className="block text-sm text-muted-foreground mb-1">Email</label>
              <div className="flex items-center gap-2 px-3 py-2 bg-surface-800 border border-border rounded-lg text-sm text-muted-foreground">
                <Mail className="w-4 h-4" />
                <span>{email}</span>
              </div>
            </div>
            <div>
              <label className="block text-sm text-muted-foreground mb-1">Role</label>
              <div className="flex items-center gap-2 px-3 py-2 bg-surface-800 border border-border rounded-lg text-sm">
                <Shield className="w-4 h-4 text-brand-400" />
                <span className="text-foreground capitalize">{user?.role}</span>
              </div>
            </div>
          </div>
          <button
            onClick={() => updateProfile.mutate()}
            disabled={updateProfile.isPending}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-brand-600 hover:bg-brand-500 text-white text-sm font-medium transition-colors disabled:opacity-50"
          >
            {updateProfile.isPending ? (
              <RefreshCw className="w-4 h-4 animate-spin" />
            ) : (
              <Save className="w-4 h-4" />
            )}
            Save Changes
          </button>
        </div>

        {/* Change Password */}
        <div className="glass-card p-5 space-y-4">
          <h2 className="text-sm font-semibold text-foreground flex items-center gap-2">
            <Shield className="w-4 h-4 text-brand-400" />
            Change Password
          </h2>
          <div className="grid gap-4">
            <div>
              <label className="block text-sm text-muted-foreground mb-1">Current Password</label>
              <input
                type="password"
                value={currentPassword}
                onChange={e => setCurrentPassword(e.target.value)}
                className="w-full px-3 py-2 bg-surface-800 border border-border rounded-lg text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-brand-500"
              />
            </div>
            <div>
              <label className="block text-sm text-muted-foreground mb-1">New Password</label>
              <input
                type="password"
                value={newPassword}
                onChange={e => setNewPassword(e.target.value)}
                className="w-full px-3 py-2 bg-surface-800 border border-border rounded-lg text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-brand-500"
              />
            </div>
            <div>
              <label className="block text-sm text-muted-foreground mb-1">Confirm New Password</label>
              <input
                type="password"
                value={confirmPassword}
                onChange={e => setConfirmPassword(e.target.value)}
                className="w-full px-3 py-2 bg-surface-800 border border-border rounded-lg text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-brand-500"
              />
            </div>
          </div>
          <button
            onClick={() => changePassword.mutate()}
            disabled={changePassword.isPending || !currentPassword || !newPassword || newPassword !== confirmPassword}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-brand-600 hover:bg-brand-500 text-white text-sm font-medium transition-colors disabled:opacity-50"
          >
            Change Password
          </button>
        </div>

        {/* MFA */}
        <div className="glass-card p-5 space-y-4">
          <h2 className="text-sm font-semibold text-foreground flex items-center gap-2">
            <Smartphone className="w-4 h-4 text-brand-400" />
            Two-Factor Authentication
          </h2>
          {user?.mfa_enabled ? (
            <div className="flex items-center gap-2 text-sm text-emerald-400">
              <CheckCircle className="w-4 h-4" />
              MFA is enabled
            </div>
          ) : mfaStep === "idle" ? (
            <div>
              <p className="text-sm text-muted-foreground mb-3">
                Add an extra layer of security to your account.
              </p>
              <button
                onClick={() => setupMFA.mutate()}
                disabled={setupMFA.isPending}
                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-brand-600 hover:bg-brand-500 text-white text-sm font-medium transition-colors disabled:opacity-50"
              >
                {setupMFA.isPending ? (
                  <RefreshCw className="w-4 h-4 animate-spin" />
                ) : (
                  <Smartphone className="w-4 h-4" />
                )}
                Setup MFA
              </button>
            </div>
          ) : (
            <div className="space-y-4">
              <p className="text-sm text-muted-foreground">
                Scan the QR code with your authenticator app, then enter the code below.
              </p>
              {mfaQrUri && (
                <div className="bg-white rounded-lg p-4 inline-block">
                  <img
                    src={`https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(mfaQrUri)}`}
                    alt="MFA QR Code"
                    className="w-48 h-48"
                  />
                </div>
              )}
              {mfaSecret && (
                <div className="bg-surface-800 rounded-lg p-3">
                  <p className="text-xs text-muted-foreground mb-1">Or enter this key manually:</p>
                  <code className="text-sm font-mono text-brand-300 break-all">{mfaSecret}</code>
                </div>
              )}
              <div className="flex items-center gap-3">
                <input
                  value={mfaCode}
                  onChange={e => setMfaCode(e.target.value)}
                  placeholder="000000"
                  maxLength={6}
                  className="w-32 px-3 py-2 bg-surface-800 border border-border rounded-lg text-sm text-foreground font-mono text-center focus:outline-none focus:ring-2 focus:ring-brand-500"
                />
                <button
                  onClick={() => enableMFA.mutate()}
                  disabled={enableMFA.isPending || mfaCode.length !== 6}
                  className="flex items-center gap-2 px-4 py-2 rounded-lg bg-brand-600 hover:bg-brand-500 text-white text-sm font-medium transition-colors disabled:opacity-50"
                >
                  Verify & Enable
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
