export type LabMission = {
  id: string;
  code: string;
  risk: string;
  title: string;
  prompt: string;
  hint: string;
  objective: string;
  flow: string[];
  vulnerableFlow?: string[];
  secureFlow?: string[];
  secureStepDetails: string[];
  vulnerableStepDetails?: string[];
  vulnerableOutcome?: string;
  secureOutcome: string;
  takeaway: string;
  recoverySteps?: { title: string; detail: string }[];
  incidentReport?: { event: string; impact: string; evidence: string; response: string };
};
