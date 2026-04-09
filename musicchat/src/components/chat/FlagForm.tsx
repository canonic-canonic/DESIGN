"use client";

import { useState } from "react";
import { flagTrack } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import type { Track } from "@/lib/types";
import { Flag, X } from "lucide-react";
import { toast } from "sonner";

const REASONS = [
  { value: "not_trini_reggae", label: "Not Trinidad reggae", desc: "This track doesn't belong in the Trini reggae collection" },
  { value: "wrong_genre", label: "Wrong genre tag", desc: "Genre metadata is incorrect" },
  { value: "bad_metadata", label: "Bad metadata", desc: "Wrong artist, title, or album info" },
  { value: "duplicate", label: "Duplicate track", desc: "This track exists more than once in the library" },
  { value: "other", label: "Other issue", desc: "Something else is wrong" },
];

interface Props {
  track: Track;
  onClose: () => void;
}

export function FlagForm({ track, onClose }: Props) {
  const { user, refreshUser } = useAuth();
  const [reason, setReason] = useState("");
  const [detail, setDetail] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async () => {
    if (!reason || submitting) return;
    setSubmitting(true);
    try {
      const result = await flagTrack(track.id, reason, detail);
      toast.success(`Flagged! +${result.credits_earned}◈ earned`);
      refreshUser();
      onClose();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Failed to flag");
    } finally {
      setSubmitting(false);
    }
  };

  if (!user) return null;

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-[200] flex items-center justify-center p-4" onClick={onClose}>
      <div className="bg-bg-card border border-border rounded-2xl max-w-md w-full p-6" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Flag size={18} className="text-red-400" />
            <h2 className="font-bold text-lg">Flag Track</h2>
          </div>
          <button onClick={onClose} className="p-1 text-gray-500 hover:text-gray-300 transition-colors">
            <X size={18} />
          </button>
        </div>

        {/* Track being flagged */}
        <div className="p-3 bg-bg-raised rounded-xl mb-4">
          <div className="font-semibold text-sm">{track.title}</div>
          <div className="text-xs text-gray-400">{track.artist}</div>
        </div>

        {/* Reason selection */}
        <div className="space-y-2 mb-4">
          {REASONS.map((r) => (
            <label
              key={r.value}
              className={`flex items-start gap-3 p-3 rounded-xl border cursor-pointer transition-colors ${
                reason === r.value
                  ? "border-accent bg-accent/5"
                  : "border-border hover:border-gray-600"
              }`}
            >
              <input
                type="radio"
                name="flag-reason"
                value={r.value}
                checked={reason === r.value}
                onChange={() => setReason(r.value)}
                className="mt-0.5 accent-accent"
              />
              <div>
                <div className="text-sm font-medium">{r.label}</div>
                <div className="text-xs text-gray-500">{r.desc}</div>
              </div>
            </label>
          ))}
        </div>

        {/* Detail */}
        <textarea
          value={detail}
          onChange={(e) => setDetail(e.target.value)}
          placeholder="Add details (optional)..."
          className="w-full p-3 bg-bg-raised border border-border rounded-xl text-sm outline-none focus:border-accent transition-colors resize-none h-20 placeholder:text-gray-600 mb-4"
        />

        {/* Submit */}
        <div className="flex items-center justify-between">
          <span className="text-xs text-gray-500">You earn +4◈ for flagging</span>
          <button
            onClick={handleSubmit}
            disabled={!reason || submitting}
            className="px-5 py-2 bg-red-500 text-white rounded-xl text-sm font-semibold hover:bg-red-600 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {submitting ? "Flagging..." : "Submit Flag"}
          </button>
        </div>
      </div>
    </div>
  );
}
