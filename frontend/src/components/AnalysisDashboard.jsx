import React from 'react';
import { Cpu, CheckCircle2 } from 'lucide-react';

export default function AnalysisDashboard({ session }) {
  const steps = [
    { id: 'DISCOVER', label: 'Local Tool Discovery', desc: 'SAST & Compiler Scan' },
    { id: 'CORRELATE', label: 'Evidence Correlation', desc: 'Finding Unification' },
    { id: 'COMPRESS', label: 'Evidence Compression', desc: 'Context Minimization' },
    { id: 'REASON', label: 'AI Reasoning Layer', desc: 'Groq GPT-OSS 120B' },
    { id: 'VALIDATE', label: 'Sandbox Validator', desc: 'Path & Action Checks' },
    { id: 'VERIFY', label: 'Deterministic Verification', desc: '4-Stage Local Check' }
  ];

  const getStepStatus = (idx) => {
    if (!session) return { tag: 'PENDING', state: 'PENDING' };
    const hasFindings = session.findings && session.findings.length > 0;
    const isCompleted = session.state === 'COMPLETED';

    if (idx <= 2) {
      if (isCompleted || idx <= 2) return { tag: '✓ EXECUTED', state: 'EXECUTED' };
      return { tag: '● RUNNING', state: 'RUNNING' };
    }

    if (isCompleted) {
      if (hasFindings) return { tag: '✓ EXECUTED', state: 'EXECUTED' };
      return { tag: 'SKIPPED (0 FLAWS)', state: 'SKIPPED' };
    }

    if (session.actions_log && session.actions_log.length > 0 && idx === 3) return { tag: '✓ EXECUTED', state: 'EXECUTED' };
    if (session.verifications && session.verifications.length > 0 && idx === 5) return { tag: '✓ EXECUTED', state: 'EXECUTED' };

    return { tag: 'PENDING', state: 'PENDING' };
  };

  return (
    <div className="hover-card animate-fade-in" style={{
      background: 'var(--color-graphite)',
      borderRadius: 'var(--radius-cards)',
      border: 'var(--hairline-border)',
      boxShadow: 'var(--card-inset-highlight)',
      padding: '24px 28px',
      marginBottom: '28px',
      color: 'var(--color-snow)'
    }}>
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        marginBottom: '20px'
      }}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          fontSize: '12px',
          color: 'var(--color-fog)',
          letterSpacing: '-0.015em'
        }}>
          <span className="status-dot-blue"></span>
          AUTONOMOUS MISSION PIPELINE CONTROL
        </div>
        <div style={{
          fontSize: '12px',
          color: 'var(--color-steel)'
        }}>
          PROJECT ID: <span style={{ color: 'var(--color-snow)', fontFamily: 'ui-monospace, monospace', fontWeight: 500 }}>{session?.project_id || 'N/A'}</span>
        </div>
      </div>

      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(6, 1fr)',
        gap: '12px'
      }}>
        {steps.map((step, idx) => {
          const { tag, state } = getStepStatus(idx);
          const isExecuted = state === 'EXECUTED';
          const isRunning = state === 'RUNNING';
          const isSkipped = state === 'SKIPPED';

          return (
            <div
              key={step.id}
              className="step-tile-hover"
              style={{
                background: 'var(--color-charcoal)',
                border: isRunning
                  ? 'var(--hairline-border-active)'
                  : 'var(--hairline-border)',
                borderRadius: 'var(--radius-sm)',
                padding: '14px 14px',
                boxShadow: isRunning ? 'var(--shadow-subtle-3)' : 'none',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
                minHeight: '84px'
              }}
            >
              <div style={{
                fontSize: '11px',
                fontWeight: 500,
                color: isExecuted ? 'var(--color-mint)' : isRunning ? 'var(--color-signal-blue)' : 'var(--color-steel)',
                marginBottom: '6px',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center'
              }}>
                <span>STEP 0{idx + 1}</span>
                <span style={{ fontSize: '10px' }}>{tag}</span>
              </div>
              <div>
                <div style={{
                  fontSize: '13px',
                  fontWeight: 400,
                  color: isSkipped ? 'var(--color-steel)' : 'var(--color-snow)',
                  letterSpacing: '-0.02em',
                  lineHeight: '1.25',
                  marginBottom: '2px'
                }}>
                  {step.label}
                </div>
                <div style={{
                  fontSize: '11px',
                  color: 'var(--color-steel)',
                  lineHeight: '1.2'
                }}>
                  {step.desc}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
