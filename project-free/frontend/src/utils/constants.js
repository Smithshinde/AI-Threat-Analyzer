export const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:4000/api/v1';

export const RISK_COLORS = {
  Critical: '#ef4444',
  High:     '#f97316',
  Medium:   '#eab308',
  Low:      '#22c55e',
};

export const SEVERITY_COLORS = {
  p1_critical: '#ef4444',
  p2_high:     '#f97316',
  p3_medium:   '#eab308',
  p4_low:      '#3b82f6',
};

export const SEVERITY_LABELS = {
  p1_critical: 'P1 — Critical',
  p2_high:     'P2 — High',
  p3_medium:   'P3 — Medium',
  p4_low:      'P4 — Low',
};

export const STATUS_COLORS = {
  open:           'bg-red-100 text-red-800',
  in_treatment:   'bg-yellow-100 text-yellow-800',
  accepted:       'bg-blue-100 text-blue-800',
  closed:         'bg-gray-100 text-gray-600',
  transferred:    'bg-purple-100 text-purple-800',
  detected:       'bg-red-100 text-red-800',
  triaged:        'bg-orange-100 text-orange-800',
  contained:      'bg-yellow-100 text-yellow-800',
  eradicated:     'bg-teal-100 text-teal-800',
  recovered:      'bg-blue-100 text-blue-800',
  draft:          'bg-gray-100 text-gray-700',
  under_review:   'bg-yellow-100 text-yellow-800',
  approved:       'bg-blue-100 text-blue-700',
  published:      'bg-green-100 text-green-800',
  retired:        'bg-gray-100 text-gray-400',
  compliant:      'bg-green-100 text-green-800',
  partial:        'bg-yellow-100 text-yellow-800',
  non_compliant:  'bg-red-100 text-red-800',
  not_assessed:   'bg-gray-100 text-gray-600',
};

export const FRAMEWORKS = ['ISO_27001', 'SOC2', 'PCI_DSS', 'NIST_CSF', 'HIPAA', 'GDPR', 'NIST_800_53', 'CIS_v8'];

export const LIKELIHOOD_OPTIONS = [
  { value: 'rare',           label: 'Rare (1)',           score: 1 },
  { value: 'unlikely',       label: 'Unlikely (2)',       score: 2 },
  { value: 'possible',       label: 'Possible (3)',       score: 3 },
  { value: 'likely',         label: 'Likely (4)',         score: 4 },
  { value: 'almost_certain', label: 'Almost Certain (5)', score: 5 },
];

export const IMPACT_OPTIONS = [
  { value: 'negligible', label: 'Negligible (1)', score: 1 },
  { value: 'minor',      label: 'Minor (2)',      score: 2 },
  { value: 'moderate',   label: 'Moderate (3)',   score: 3 },
  { value: 'major',      label: 'Major (4)',      score: 4 },
  { value: 'critical',   label: 'Critical (5)',   score: 5 },
];
