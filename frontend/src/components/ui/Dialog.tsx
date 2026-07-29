"use client";

import * as DialogPrimitive from "@radix-ui/react-dialog";
import { motion } from "framer-motion";
import { cn } from "@/lib/utils";

// Shared backdrop for every Dialog-based modal (ScanModal, FindingDetailModal,
// the inline "New Scan" modal). Deliberately no blur -- a blurred backdrop
// smears whatever's behind it into illegibility, which is content-dependent
// and far more disruptive over a bright, text-dense page than a dark one.
// `bg-overlay` is a themed token (see globals.css) instead of a hardcoded
// black, so it dims predictably in both themes rather than crushing a light
// page while barely showing on a dark one.
export function DialogOverlay({
  className,
  ...props
}: React.ComponentProps<typeof motion.div>) {
  return (
    <DialogPrimitive.Overlay asChild>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        className={cn("fixed inset-0 z-50 bg-overlay/60", className)}
        {...props}
      />
    </DialogPrimitive.Overlay>
  );
}
