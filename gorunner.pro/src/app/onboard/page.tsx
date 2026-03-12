"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { onboardProfile, onboardVerify, onboardComplete } from "@/lib/api";
import { toast } from "sonner";
import {
  User,
  Shield,
  Search,
  Wallet,
  FileText,
  Check,
  ArrowRight,
} from "lucide-react";
import { cn } from "@/lib/utils";

const STEPS = [
  { icon: User, label: "Profile" },
  { icon: Shield, label: "Identity" },
  { icon: Search, label: "Background" },
  { icon: Wallet, label: "Wallet" },
  { icon: FileText, label: "Agreements" },
];

export default function OnboardPage() {
  const router = useRouter();
  const { identity } = useAuth();
  const [step, setStep] = useState(1);
  const [submitting, setSubmitting] = useState(false);

  // Step 1 form
  const [firstName, setFirstName] = useState("");
  const [lastName, setLastName] = useState("");
  const [phone, setPhone] = useState("");
  const [vehicleType, setVehicleType] = useState("car");

  // Step 2 form
  const [credentialType, setCredentialType] = useState("business_license");
  const [licenseNumber, setLicenseNumber] = useState("");

  // Step 5 form
  const [termsAccepted, setTermsAccepted] = useState(false);
  const [icAccepted, setIcAccepted] = useState(false);

  async function handleStep1() {
    if (!identity || !firstName || !phone) return;
    setSubmitting(true);
    try {
      await onboardProfile({
        user_id: identity.userId,
        first_name: firstName,
        last_name: lastName,
        phone,
        vehicle_type: vehicleType,
      });
      setStep(2);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed");
    } finally {
      setSubmitting(false);
    }
  }

  async function handleStep2() {
    if (!identity) return;
    setSubmitting(true);
    try {
      await onboardVerify({
        user_id: identity.userId,
        credential_type: credentialType,
        license_number: licenseNumber,
      });
      setStep(3);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed");
    } finally {
      setSubmitting(false);
    }
  }

  async function handleStep5() {
    if (!identity || !termsAccepted || !icAccepted) return;
    setSubmitting(true);
    try {
      await onboardComplete(identity.userId);
      toast.success("Welcome aboard! Startup Credits minted.");
      router.push("/runner");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="min-h-screen">
      {/* Header */}
      <div className="bg-gradient-runner px-4 pt-12 pb-6 text-white">
        <div className="max-w-lg mx-auto">
          <h1 className="text-xl font-bold">Runner Onboarding</h1>
          <p className="text-sm text-white/70">
            Step {step} of 5 — {STEPS[step - 1]?.label}
          </p>
        </div>
      </div>

      {/* Step indicator — Robert's circles + connecting line */}
      <div className="max-w-lg mx-auto px-8 py-6">
        <div className="flex items-center justify-between relative">
          {/* Connecting line */}
          <div className="absolute top-4 left-4 right-4 h-0.5 bg-gray-200 dark:bg-gray-700" />
          <div
            className="absolute top-4 left-4 h-0.5 bg-gradient-runner transition-all"
            style={{
              width: `${((step - 1) / (STEPS.length - 1)) * 100}%`,
            }}
          />

          {STEPS.map(({ icon: Icon, label }, i) => {
            const n = i + 1;
            const done = n < step;
            const current = n === step;
            return (
              <div
                key={label}
                className="relative z-10 flex flex-col items-center gap-1"
              >
                <div
                  className={cn(
                    "h-8 w-8 rounded-full flex items-center justify-center text-xs font-bold transition-colors",
                    done
                      ? "bg-green-500 text-white"
                      : current
                        ? "bg-gradient-runner text-white"
                        : "bg-gray-200 dark:bg-gray-700 text-gray-500"
                  )}
                >
                  {done ? <Check className="h-4 w-4" /> : n}
                </div>
                <span
                  className={cn(
                    "text-[9px] font-medium",
                    current
                      ? "text-orange-600"
                      : "text-gray-400"
                  )}
                >
                  {label}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      <div className="max-w-lg mx-auto px-4 pb-8 space-y-4">
        {/* Step 1: Profile */}
        {step === 1 && (
          <div className="space-y-4">
            <div>
              <label className="text-sm font-semibold mb-1 block">
                First Name
              </label>
              <input
                value={firstName}
                onChange={(e) => setFirstName(e.target.value)}
                className="w-full rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 px-3 py-2 text-sm"
                required
              />
            </div>
            <div>
              <label className="text-sm font-semibold mb-1 block">
                Last Name
              </label>
              <input
                value={lastName}
                onChange={(e) => setLastName(e.target.value)}
                className="w-full rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 px-3 py-2 text-sm"
              />
            </div>
            <div>
              <label className="text-sm font-semibold mb-1 block">
                Phone
              </label>
              <input
                type="tel"
                value={phone}
                onChange={(e) => setPhone(e.target.value)}
                className="w-full rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 px-3 py-2 text-sm"
                required
              />
            </div>
            <div>
              <label className="text-sm font-semibold mb-1 block">
                Vehicle Type
              </label>
              <div className="flex gap-2">
                {["car", "truck", "van"].map((v) => (
                  <button
                    key={v}
                    type="button"
                    onClick={() => setVehicleType(v)}
                    className={`flex-1 rounded-lg border py-2 text-sm font-medium capitalize ${
                      vehicleType === v
                        ? "border-orange-500 bg-orange-50 dark:bg-orange-900/20"
                        : "border-gray-200 dark:border-gray-800"
                    }`}
                  >
                    {v}
                  </button>
                ))}
              </div>
            </div>
            <button
              onClick={handleStep1}
              disabled={!firstName || !phone || submitting}
              className="w-full flex items-center justify-center gap-2 rounded-xl bg-gradient-runner text-white font-semibold py-3 disabled:opacity-50"
            >
              {submitting ? "Saving..." : "Continue"}
              <ArrowRight className="h-4 w-4" />
            </button>
          </div>
        )}

        {/* Step 2: Identity / KYC */}
        {step === 2 && (
          <div className="space-y-4">
            <p className="text-sm text-gray-500">
              Submit your professional credentials for verification.
              Required for gated task types (inspections, appraisals,
              title, closing).
            </p>
            <div>
              <label className="text-sm font-semibold mb-1 block">
                Credential Type
              </label>
              <select
                value={credentialType}
                onChange={(e) => setCredentialType(e.target.value)}
                className="w-full rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 px-3 py-2 text-sm"
              >
                <option value="business_license">Business License</option>
                <option value="FL_468">
                  FL Home Inspector (Statute 468)
                </option>
                <option value="FL_FREAB_USPAP">
                  FL Appraiser (FREAB + USPAP)
                </option>
                <option value="FL_626">
                  FL Title Agent (Statute 626)
                </option>
                <option value="FL_626_NMLS">
                  FL Closing Agent (626 + NMLS)
                </option>
                <option value="real_estate_license">
                  Real Estate License
                </option>
              </select>
            </div>
            <div>
              <label className="text-sm font-semibold mb-1 block">
                License Number
              </label>
              <input
                value={licenseNumber}
                onChange={(e) => setLicenseNumber(e.target.value)}
                placeholder="e.g., 0225234172"
                className="w-full rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 px-3 py-2 text-sm"
              />
            </div>
            <div className="flex gap-2">
              <button
                onClick={() => setStep(3)}
                className="flex-1 rounded-xl border border-gray-300 py-3 text-sm font-medium"
              >
                Skip for now
              </button>
              <button
                onClick={handleStep2}
                disabled={submitting}
                className="flex-1 rounded-xl bg-gradient-runner text-white font-semibold py-3 disabled:opacity-50"
              >
                {submitting ? "Verifying..." : "Submit"}
              </button>
            </div>
          </div>
        )}

        {/* Step 3: Background (deferred) */}
        {step === 3 && (
          <div className="space-y-4 text-center py-8">
            <Search className="h-12 w-12 mx-auto text-gray-300" />
            <h3 className="font-semibold">Background Check</h3>
            <p className="text-sm text-gray-500">
              Background verification is coming in Q2 2026. For now,
              your credentials and governance attestation serve as your
              trust layer.
            </p>
            <button
              onClick={() => setStep(4)}
              className="rounded-xl bg-gradient-runner text-white font-semibold px-8 py-3"
            >
              Continue
            </button>
          </div>
        )}

        {/* Step 4: Wallet */}
        {step === 4 && (
          <div className="space-y-4 text-center py-4">
            <div className="h-16 w-16 mx-auto rounded-full bg-gradient-coin flex items-center justify-center text-2xl">
              ∩
            </div>
            <h3 className="font-semibold text-lg">∩ Credit Wallet</h3>
            <p className="text-sm text-gray-500 max-w-xs mx-auto">
              When you complete onboarding, your VAULT wallet is
              bootstrapped with startup Credits. Every task you complete
              earns more Credits — tracked on an immutable, hash-chained
              ledger.
            </p>
            <div className="rounded-lg bg-amber-50 dark:bg-amber-900/10 p-4 text-left space-y-2">
              <div className="flex justify-between text-sm">
                <span>Signup bonus</span>
                <span className="font-bold text-amber-600">∩50</span>
              </div>
              <div className="flex justify-between text-sm">
                <span>Per task</span>
                <span className="font-bold text-amber-600">3-25 COIN</span>
              </div>
              <div className="flex justify-between text-sm">
                <span>Full listing</span>
                <span className="font-bold text-amber-600">161 COIN</span>
              </div>
            </div>
            <button
              onClick={() => setStep(5)}
              className="rounded-xl bg-gradient-runner text-white font-semibold px-8 py-3"
            >
              Continue
            </button>
          </div>
        )}

        {/* Step 5: Agreements */}
        {step === 5 && (
          <div className="space-y-4">
            <p className="text-sm text-gray-500">
              Review and accept the following agreements to activate
              your runner account.
            </p>

            <label className="flex items-start gap-3 rounded-lg border border-gray-200 dark:border-gray-800 p-4 cursor-pointer">
              <input
                type="checkbox"
                checked={termsAccepted}
                onChange={(e) => setTermsAccepted(e.target.checked)}
                className="mt-0.5 h-4 w-4 rounded border-gray-300"
              />
              <div>
                <div className="text-sm font-semibold">
                  Terms of Service
                </div>
                <div className="text-xs text-gray-500">
                  I agree to the GoRunner Terms of Service and
                  acknowledge the CANONIC governance framework.
                </div>
              </div>
            </label>

            <label className="flex items-start gap-3 rounded-lg border border-gray-200 dark:border-gray-800 p-4 cursor-pointer">
              <input
                type="checkbox"
                checked={icAccepted}
                onChange={(e) => setIcAccepted(e.target.checked)}
                className="mt-0.5 h-4 w-4 rounded border-gray-300"
              />
              <div>
                <div className="text-sm font-semibold">
                  Independent Contractor Agreement
                </div>
                <div className="text-xs text-gray-500">
                  I confirm that I am an independent contractor and
                  understand the task-based compensation model.
                </div>
              </div>
            </label>

            <button
              onClick={handleStep5}
              disabled={!termsAccepted || !icAccepted || submitting}
              className="w-full rounded-xl bg-gradient-to-r from-green-500 to-emerald-500 text-white font-semibold py-3 disabled:opacity-50"
            >
              {submitting
                ? "Activating..."
                : "Complete Onboarding & Mint Credits"}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
