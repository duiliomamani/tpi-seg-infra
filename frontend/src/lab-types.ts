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
  codeExample?: {
    path: string;
    vulnerable: string;
    secure: string;
    explanation: string;
  };
  quiz?: {
    question: string;
    choices: string[];
    correctIndex: number;
    explanation: string;
  };
};

export type TraceEntry = {
  stage: string;
  status: "info" | "allowed" | "blocked" | "vulnerable" | "executed" | "simulated";
  detail: string;
};
