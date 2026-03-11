/**
 * RUNNER/CONSTANTS — Generated from SERVICES/TALK/RUNNER/CANON.json.
 * _generated: { contract: "SERVICES/TALK/RUNNER/CANON.md", rule: "edit the contract or compiler — not this file" }
 */

export const TASK_PRICES = {
  "lockbox_install": 3,
  "lockbox_remove": 3,
  "yard_sign_install": 3,
  "yard_sign_remove": 3,
  "photo_shoot": 10,
  "staging": 8,
  "inspection": 10,
  "appraisal": 10,
  "title": 10,
  "open_house": 8,
  "showing": 5,
  "cma": 5,
  "contract": 15,
  "closing": 25,
  "flyer_delivery": 3,
  "vendor_meetup": 5,
  "key_run": 3
};

export const KYC_REQUIRED = {
  "photo_shoot": "business_license",
  "staging": "business_license",
  "inspection": "FL_468",
  "appraisal": "FL_FREAB_USPAP",
  "title": "FL_626",
  "closing": "FL_626_NMLS"
};

export const TASK_LIFECYCLE = ["posted", "assigned", "accepted", "in_progress", "completed", "rated", "cancelled"];

export const TRANSITIONS = {
  "posted": [
    "assigned",
    "cancelled"
  ],
  "assigned": [
    "accepted",
    "cancelled"
  ],
  "accepted": [
    "in_progress",
    "cancelled"
  ],
  "in_progress": [
    "completed",
    "cancelled"
  ],
  "completed": [
    "rated"
  ]
};

export const STAGE_TASKS = {
  "inquiry": [
    "cma"
  ],
  "match": [
    "yard_sign_install",
    "lockbox_install"
  ],
  "show": [
    "showing",
    "photo_shoot"
  ],
  "offer": [
    "contract",
    "inspection",
    "appraisal"
  ],
  "negotiate": [
    "title"
  ],
  "close": [
    "closing"
  ]
};

export const ROLES = ["Requester", "Runner", "Ops"];
