import React, { useState, useEffect } from 'react';
import { ShieldAlert, Cpu, CheckCircle2, XCircle, Activity, Lock, Code2, AlertTriangle, ArrowLeft, Check, RefreshCw, Terminal, FileCode, Download, FileText, ExternalLink, Eye, X } from 'lucide-react';
import ProjectUpload from './components/ProjectUpload';
import AnalysisDashboard from './components/AnalysisDashboard';
import { 
  startAnalysis, 
  getAnalysisStatus, 
  getReportView, 
  getReportViewUrl,
  getReportDownloadUrl, 
  getPatchDownloadUrl,
  getCorrectedCodeView,
  getCorrectedCodeDownloadUrl
} from './services/api';

export default function App() {
  const [projectData, setProjectData] = useState(null);
  const [session, setSession] = useState(null);
  const [findings, setFindings] = useState([]);
  const [compressedPackets, setCompressedPackets] = useState([]);
  const [actionsLog, setActionsLog] = useState([]);
  const [auditTrail, setAuditTrail] = useState([]);
  const [loading, setLoading] = useState(false);

  // Active Tab state for de-cluttered bottom results panel
  const [activeTab, setActiveTab] = useState('verification'); // 'verification' | 'patch' | 'audit'

  // Modal Report Viewer state
  const [showReportModal, setShowReportModal] = useState(false);
  const [reportText, setReportText] = useState('');
  const [reportLoading, setReportLoading] = useState(false);

  // Modal Corrected Code Viewer state
  const [showCodeModal, setShowCodeModal] = useState(false);
  const [codeText, setCodeText] = useState('');
  const [codeFilename, setCodeFilename] = useState('');
  const [codeLoading, setCodeLoading] = useState(false);

  // Keyboard shortcut listener for ESC key to close modals
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') {
        handleCloseModals();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const handleUploadSuccess = async (data) => {
    setProjectData(data);
    setLoading(true);
    try {
      const res = await startAnalysis(data.project_id);
      setSession(res.session);
      if (res.session.findings) setFindings(res.session.findings);
      if (res.session.compressed_packets) setCompressedPackets(res.session.compressed_packets);
      if (res.session.actions_log) setActionsLog(res.session.actions_log);
      if (res.session.audit_trail) setAuditTrail(res.session.audit_trail);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  // Back Button handler to return to 1st screen (Project Upload)
  const handleResetToUpload = () => {
    setProjectData(null);
    setSession(null);
    setFindings([]);
    setCompressedPackets([]);
    setActionsLog([]);
    setAuditTrail([]);
    setLoading(false);
    handleCloseModals();
  };

  const handleOpenReportModal = async (e) => {
    if (e) e.preventDefault();
    if (!projectData?.project_id) return;
    document.body.style.overflow = 'hidden';
    setShowReportModal(true);
    setReportLoading(true);
    try {
      const text = await getReportView(projectData.project_id);
      setReportText(text || 'No report content available.');
    } catch (err) {
      console.error('Report load error:', err);
      setReportText('Failed to load report content from server.');
    } finally {
      setReportLoading(false);
    }
  };

  const handleOpenCodeModal = async (e) => {
    if (e) e.preventDefault();
    if (!projectData?.project_id) return;
    document.body.style.overflow = 'hidden';
    setShowCodeModal(true);
    setCodeLoading(true);
    try {
      const text = await getCorrectedCodeView(projectData.project_id);
      setCodeText(text || '// No corrected source code found.');
      setCodeFilename('Corrected_Target_Source.c');
    } catch (err) {
      console.error('Code load error:', err);
      setCodeText('Failed to load corrected source code content.');
      setCodeFilename('source.c');
    } finally {
      setCodeLoading(false);
    }
  };

  const handleCloseModals = () => {
    document.body.style.overflow = 'unset';
    setShowReportModal(false);
    setShowCodeModal(false);
  };

  useEffect(() => {
    if (!projectData?.project_id) return;
    const interval = setInterval(async () => {
      try {
        const currentStatus = await getAnalysisStatus(projectData.project_id);
        setSession(currentStatus);
        if (currentStatus.findings) setFindings(currentStatus.findings);
        if (currentStatus.compressed_packets) setCompressedPackets(currentStatus.compressed_packets);
        if (currentStatus.actions_log) setActionsLog(currentStatus.actions_log);
        if (currentStatus.audit_trail) setAuditTrail(currentStatus.audit_trail);
      } catch (err) {
        console.error('Auto-refresh polling error:', err);
      }
    }, 2000);
    return () => clearInterval(interval);
  }, [projectData]);

  // Default Style Reference Badges
  const renderAIModeBadge = () => {
    const mode = session?.ai_mode || 'LOCAL_FALLBACK';
    if (mode === 'LIVE_AI') {
      return (
        <div style={{
          background: 'rgba(59, 130, 246, 0.1)',
          border: '0.5px solid rgba(59, 130, 246, 0.3)',
          color: 'var(--color-signal-blue)',
          padding: '6px 14px',
          borderRadius: 'var(--radius-pills)',
          fontSize: '12px',
          fontWeight: '400',
          display: 'flex',
          alignItems: 'center',
          gap: '6px'
        }}>
          <span className="status-dot-blue"></span>
          LIVE AI (GROQ GPT-OSS-120B)
        </div>
      );
    } else if (mode === 'RATE_LIMITED') {
      return (
        <div style={{
          background: 'rgba(234, 88, 12, 0.1)',
          border: '0.5px solid rgba(234, 88, 12, 0.3)',
          color: 'var(--color-ember)',
          padding: '6px 14px',
          borderRadius: 'var(--radius-pills)',
          fontSize: '12px',
          fontWeight: '400',
          display: 'flex',
          alignItems: 'center',
          gap: '6px'
        }}>
          <span className="status-dot-amber"></span>
          RATE LIMITED (LOCAL FALLBACK ACTIVE)
        </div>
      );
    } else {
      return (
        <div style={{
          background: 'rgba(255, 255, 255, 0.05)',
          border: 'var(--hairline-border)',
          color: 'var(--color-steel)',
          padding: '6px 14px',
          borderRadius: 'var(--radius-pills)',
          fontSize: '12px',
          fontWeight: '400',
          display: 'flex',
          alignItems: 'center',
          gap: '6px'
        }}>
          <span className="status-dot-slate"></span>
          LOCAL FALLBACK MODE
        </div>
      );
    }
  };

  const isCompleted = session?.state === 'COMPLETED';

  return (
    <div style={{
      backgroundColor: 'var(--color-void)',
      minHeight: '100vh',
      color: 'var(--color-snow)',
      fontFamily: 'var(--font-inter)'
    }}>
      {/* Sticky Nav Header — Frosted Glass Mission Control Style */}
      <header style={{
        background: 'rgba(11, 12, 14, 0.85)',
        backdropFilter: 'blur(10px)',
        borderBottom: 'var(--hairline-border)',
        padding: '0 32px',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        height: '68px',
        position: 'sticky',
        top: 0,
        zIndex: 50
      }}>
        {/* Left Brand Wordmark */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{
            fontSize: '15px',
            fontWeight: '400',
            letterSpacing: '-0.02em',
            color: 'var(--color-snow)',
            display: 'flex',
            alignItems: 'center',
            gap: '8px'
          }}>
            <span className="status-dot-blue"></span>
            VAJRA
          </div>
          <span style={{ color: 'rgba(255,255,255,0.15)', fontSize: '14px' }}>|</span>
          <div style={{
            fontSize: '12px',
            color: 'var(--color-fog)',
            letterSpacing: '-0.015em'
          }}>
            Verified Autonomous Joint Reasoning & Remediation Architecture
          </div>
        </div>

        {/* Header Right — Single Back Button & Status Badges */}
        <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
          {projectData && (
            <button
              onClick={handleResetToUpload}
              className="btn-back-hover"
              style={{
                background: 'rgba(255, 255, 255, 0.05)',
                border: 'var(--hairline-border)',
                color: 'var(--color-snow)',
                padding: '7px 16px',
                borderRadius: 'var(--radius-pills)',
                fontSize: '12px',
                fontWeight: '400',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '6px'
              }}
            >
              <ArrowLeft size={14} /> Back to Upload
            </button>
          )}

          {renderAIModeBadge()}
          <div style={{
            background: 'rgba(255, 255, 255, 0.05)',
            border: 'var(--hairline-border)',
            color: 'var(--color-arc-blue)',
            padding: '6px 14px',
            borderRadius: 'var(--radius-pills)',
            fontSize: '12px',
            fontWeight: '400'
          }}>
            MODEL: OPENAI/GPT-OSS-120B
          </div>
        </div>
      </header>

      {/* Main Container — 1400px Max Width Centered */}
      <main style={{
        maxWidth: 'var(--page-max-width)',
        margin: '0 auto',
        padding: '32px 24px 96px 24px'
      }}>
        {!projectData ? (
          <ProjectUpload onUploadSuccess={handleUploadSuccess} />
        ) : (
          <div className="animate-fade-in">
            <AnalysisDashboard session={session} />

            {/* Findings & Evidence Grid (2-Column Spacious Layout) */}
            <div style={{
              display: 'grid',
              gridTemplateColumns: '1fr 1fr',
              gap: '24px',
              marginBottom: '32px'
            }}>
              {/* Vulnerability Findings Detail Panel */}
              <div className="hover-card" style={{
                background: 'var(--color-graphite)',
                borderRadius: 'var(--radius-cards)',
                border: 'var(--hairline-border)',
                boxShadow: 'var(--card-inset-highlight)',
                padding: '24px 28px'
              }}>
                <div style={{
                  fontSize: '12px',
                  color: 'var(--color-fog)',
                  letterSpacing: '-0.015em',
                  marginBottom: '12px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px'
                }}>
                  <span className="status-dot-blue"></span>
                  VULNERABILITY FINDINGS DETAIL
                </div>

                <h3 style={{
                  margin: '0 0 20px 0',
                  fontSize: '24px',
                  lineHeight: '1.25',
                  letterSpacing: '-0.64px',
                  fontWeight: '400',
                  color: 'var(--color-snow)'
                }}>
                  Security Flaws Detected
                </h3>

                {findings.length === 0 ? (
                  isCompleted ? (
                    <div style={{
                      background: 'var(--color-charcoal)',
                      padding: '16px 20px',
                      borderRadius: 'var(--radius-sm)',
                      border: 'var(--hairline-border)',
                      color: 'var(--color-mint)',
                      fontSize: '13px',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '8px'
                    }}>
                      <Check size={16} color="var(--color-mint)" /> 0 Security Flaws Discovered — Target code analysis clean.
                    </div>
                  ) : (
                    <p style={{ color: 'var(--color-steel)', fontSize: '14px', margin: 0 }}>Scanning C/C++ source target for security flaws...</p>
                  )
                ) : (
                  findings.map((f) => (
                    <div key={f.finding_id} style={{
                      background: 'var(--color-charcoal)',
                      padding: '18px 20px',
                      borderRadius: 'var(--radius-sm)',
                      marginBottom: '16px',
                      border: 'var(--hairline-border)',
                      borderLeft: `3px solid ${f.status === 'VERIFIED' ? 'var(--color-mint)' : 'var(--color-coral)'}`
                    }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                        <span style={{ color: 'var(--color-snow)', fontWeight: 500, fontSize: '15px' }}>
                          {f.finding_id}: {f.cwe}
                        </span>
                        <span style={{
                          color: f.status === 'VERIFIED' ? 'var(--color-mint)' : 'var(--color-coral)',
                          background: 'rgba(255,255,255,0.03)',
                          border: 'var(--hairline-border-subtle)',
                          padding: '2px 8px',
                          borderRadius: '4px',
                          fontSize: '11px',
                          fontFamily: 'ui-monospace, monospace'
                        }}>
                          {f.status}
                        </span>
                      </div>

                      <div style={{ fontSize: '12px', color: 'var(--color-steel)', marginBottom: '8px', wordBreak: 'break-all' }}>
                        Target: <code style={{ color: 'var(--color-arc-blue)', background: 'rgba(0,0,0,0.3)', padding: '2px 6px', borderRadius: '4px' }}>
                          {f.file}:{f.line} ({f.function || 'unknown'})
                        </code>
                      </div>

                      <p style={{ fontSize: '13px', color: 'var(--color-fog)', margin: '0 0 12px 0', lineHeight: '1.45' }}>
                        {f.description}
                      </p>

                      {actionsLog.length > 0 && (
                        <div style={{
                          marginTop: '12px',
                          padding: '12px 14px',
                          background: 'var(--color-void)',
                          borderRadius: 'var(--radius-xs)',
                          border: 'var(--hairline-border-subtle)',
                          fontSize: '12px',
                          color: 'var(--color-chalk)'
                        }}>
                          <div style={{ marginBottom: '6px', lineHeight: '1.4' }}>
                            <strong style={{ color: 'var(--color-snow)' }}>AI Reasoning:</strong> {actionsLog[0].reason}
                          </div>
                          <div style={{ color: 'var(--color-steel)', display: 'flex', gap: '16px' }}>
                            <span>Action: <code style={{ color: 'var(--color-arc-blue)' }}>{actionsLog[0].action_type}</code></span>
                            <span>Confidence: <code style={{ color: 'var(--color-mint)' }}>{actionsLog[0].confidence}</code></span>
                          </div>
                        </div>
                      )}
                    </div>
                  ))
                )}
              </div>

              {/* Compressed Evidence Packet Panel */}
              <div className="hover-card" style={{
                background: 'var(--color-graphite)',
                borderRadius: 'var(--radius-cards)',
                border: 'var(--hairline-border)',
                boxShadow: 'var(--card-inset-highlight)',
                padding: '24px 28px'
              }}>
                <div style={{
                  fontSize: '12px',
                  color: 'var(--color-fog)',
                  letterSpacing: '-0.015em',
                  marginBottom: '12px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px'
                }}>
                  <span className="status-dot-blue"></span>
                  COMPRESSED EVIDENCE PACKET
                </div>

                <h3 style={{
                  margin: '0 0 20px 0',
                  fontSize: '24px',
                  lineHeight: '1.25',
                  letterSpacing: '-0.64px',
                  fontWeight: '400',
                  color: 'var(--color-snow)'
                }}>
                  Pre-LLM Evidence Context
                </h3>

                {compressedPackets.length === 0 ? (
                  isCompleted ? (
                    <div style={{
                      background: 'var(--color-charcoal)',
                      padding: '16px 20px',
                      borderRadius: 'var(--radius-sm)',
                      border: 'var(--hairline-border)',
                      color: 'var(--color-steel)',
                      fontSize: '13px'
                    }}>
                      No context compression required (0 active findings).
                    </div>
                  ) : (
                    <p style={{ color: 'var(--color-steel)', fontSize: '14px', margin: 0 }}>Waiting for evidence compression...</p>
                  )
                ) : (
                  <div>
                    {/* Metadata Header Badges */}
                    <div style={{
                      display: 'flex',
                      gap: '12px',
                      marginBottom: '14px',
                      fontSize: '12px',
                      color: 'var(--color-steel)'
                    }}>
                      <span style={{ background: 'var(--color-charcoal)', padding: '4px 10px', borderRadius: '4px', border: 'var(--hairline-border)' }}>
                        Line: <code style={{ color: 'var(--color-arc-blue)' }}>{compressedPackets[0]?.line || 'N/A'}</code>
                      </span>
                      <span style={{ background: 'var(--color-charcoal)', padding: '4px 10px', borderRadius: '4px', border: 'var(--hairline-border)' }}>
                        Function: <code style={{ color: 'var(--color-snow)' }}>{compressedPackets[0]?.function || 'N/A'}</code>
                      </span>
                      <span style={{ background: 'var(--color-charcoal)', padding: '4px 10px', borderRadius: '4px', border: 'var(--hairline-border)' }}>
                        State: <code style={{ color: 'var(--color-mint)' }}>{compressedPackets[0]?.workflow_state || 'DISCOVERED'}</code>
                      </span>
                    </div>

                    {/* Source Code Viewer */}
                    <div style={{
                      background: 'var(--color-void)',
                      border: 'var(--hairline-border)',
                      borderRadius: 'var(--radius-sm)',
                      overflow: 'hidden'
                    }}>
                      <div style={{
                        background: 'var(--color-charcoal)',
                        padding: '8px 14px',
                        borderBottom: 'var(--hairline-border-subtle)',
                        fontSize: '11px',
                        color: 'var(--color-steel)',
                        display: 'flex',
                        justifyContent: 'space-between'
                      }}>
                        <span>RELEVANT SOURCE CODE CONTEXT</span>
                        <span>{compressedPackets[0]?.relevant_source?.split('\n').length || 0} Lines</span>
                      </div>
                      <pre style={{
                        padding: '16px',
                        overflowX: 'auto',
                        fontSize: '12px',
                        lineHeight: '1.5',
                        color: 'var(--color-mint)',
                        maxHeight: '340px',
                        margin: 0
                      }}>
                        {compressedPackets[0]?.relevant_source || JSON.stringify(compressedPackets[0], null, 2)}
                      </pre>
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* DE-CLUTTERED SEGMENTED CONTROL SURFACE (TABBED RESULTS) */}
            <div style={{
              background: 'var(--color-graphite)',
              borderRadius: 'var(--radius-cards)',
              border: 'var(--hairline-border)',
              boxShadow: 'var(--card-inset-highlight)',
              padding: '24px 28px',
              marginBottom: '32px'
            }}>
              {/* Tab Navigation Bar */}
              <div style={{
                display: 'flex',
                gap: '8px',
                borderBottom: 'var(--hairline-border)',
                paddingBottom: '16px',
                marginBottom: '24px'
              }}>
                <button
                  onClick={() => setActiveTab('verification')}
                  style={{
                    background: activeTab === 'verification' ? 'var(--color-charcoal)' : 'transparent',
                    color: activeTab === 'verification' ? 'var(--color-snow)' : 'var(--color-steel)',
                    border: activeTab === 'verification' ? 'var(--hairline-border-active)' : '1px solid transparent',
                    padding: '8px 18px',
                    borderRadius: 'var(--radius-pills)',
                    fontSize: '13px',
                    fontWeight: activeTab === 'verification' ? 500 : 400,
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                    transition: 'all 0.2s ease'
                  }}
                >
                  <CheckCircle2 size={16} color={activeTab === 'verification' ? 'var(--color-mint)' : 'var(--color-steel)'} />
                  Verification & Audit Report
                </button>

                <button
                  onClick={() => setActiveTab('patch')}
                  style={{
                    background: activeTab === 'patch' ? 'var(--color-charcoal)' : 'transparent',
                    color: activeTab === 'patch' ? 'var(--color-snow)' : 'var(--color-steel)',
                    border: activeTab === 'patch' ? 'var(--hairline-border-active)' : '1px solid transparent',
                    padding: '8px 18px',
                    borderRadius: 'var(--radius-pills)',
                    fontSize: '13px',
                    fontWeight: activeTab === 'patch' ? 500 : 400,
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                    transition: 'all 0.2s ease'
                  }}
                >
                  <Code2 size={16} color={activeTab === 'patch' ? 'var(--color-arc-blue)' : 'var(--color-steel)'} />
                  Patch & Corrected Code
                </button>

                <button
                  onClick={() => setActiveTab('audit')}
                  style={{
                    background: activeTab === 'audit' ? 'var(--color-charcoal)' : 'transparent',
                    color: activeTab === 'audit' ? 'var(--color-snow)' : 'var(--color-steel)',
                    border: activeTab === 'audit' ? 'var(--hairline-border-active)' : '1px solid transparent',
                    padding: '8px 18px',
                    borderRadius: 'var(--radius-pills)',
                    fontSize: '13px',
                    fontWeight: activeTab === 'audit' ? 500 : 400,
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                    transition: 'all 0.2s ease'
                  }}
                >
                  <Terminal size={16} color={activeTab === 'audit' ? 'var(--color-signal-blue)' : 'var(--color-steel)'} />
                  Mission Audit Trail ({auditTrail.length})
                </button>
              </div>

              {/* TAB 1: VERIFICATION & EXECUTIVE REPORT */}
              {activeTab === 'verification' && (
                <div className="animate-fade-in">
                  {/* Deterministic Verification Engine */}
                  {session?.verifications && session.verifications.length > 0 ? (
                    <div style={{ marginBottom: '28px' }}>
                      <div style={{
                        fontSize: '12px',
                        color: session.verifications[0].status === 'VERIFIED' ? 'var(--color-mint)' : 'var(--color-coral)',
                        letterSpacing: '-0.015em',
                        marginBottom: '12px',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '6px'
                      }}>
                        {session.verifications[0].status === 'VERIFIED' ? <CheckCircle2 size={16} color="var(--color-mint)" /> : <XCircle size={16} color="var(--color-coral)" />}
                        DETERMINISTIC LOCAL VERIFICATION ENGINE
                      </div>

                      <h3 style={{
                        margin: '0 0 8px 0',
                        fontSize: '26px',
                        fontWeight: '400',
                        color: 'var(--color-snow)'
                      }}>
                        Final Outcome: <span style={{ color: session.verifications[0].status === 'VERIFIED' ? 'var(--color-mint)' : 'var(--color-coral)' }}>{session.verifications[0].status}</span>
                      </h3>

                      <div style={{
                        fontSize: '13px',
                        color: 'var(--color-steel)',
                        marginBottom: '20px',
                        background: 'var(--color-charcoal)',
                        padding: '10px 14px',
                        borderRadius: 'var(--radius-xs)',
                        border: 'var(--hairline-border-subtle)'
                      }}>
                        {session.verifications[0].details}
                      </div>

                      {/* 4-Stage Grid */}
                      <div style={{
                        display: 'grid',
                        gridTemplateColumns: 'repeat(4, 1fr)',
                        gap: '16px'
                      }}>
                        <div style={{ background: 'var(--color-charcoal)', border: 'var(--hairline-border)', padding: '16px 18px', borderRadius: 'var(--radius-sm)' }}>
                          <div style={{ fontSize: '11px', color: 'var(--color-steel)', marginBottom: '6px' }}>1. COMPILATION</div>
                          <div style={{ fontSize: '18px', fontWeight: 400, color: session.verifications[0].compilation_passed ? 'var(--color-mint)' : 'var(--color-coral)' }}>
                            {session.verifications[0].compilation_passed ? 'PASS' : 'FAIL'}
                          </div>
                        </div>

                        <div style={{ background: 'var(--color-charcoal)', border: 'var(--hairline-border)', padding: '16px 18px', borderRadius: 'var(--radius-sm)' }}>
                          <div style={{ fontSize: '11px', color: 'var(--color-steel)', marginBottom: '6px' }}>2. POV REPLAY</div>
                          <div style={{ fontSize: '18px', fontWeight: 400, color: session.verifications[0].pov_replay_passed ? 'var(--color-mint)' : 'var(--color-coral)' }}>
                            {session.verifications[0].pov_replay_passed ? 'PASS' : 'FAIL'}
                          </div>
                        </div>

                        <div style={{ background: 'var(--color-charcoal)', border: 'var(--hairline-border)', padding: '16px 18px', borderRadius: 'var(--radius-sm)' }}>
                          <div style={{ fontSize: '11px', color: 'var(--color-steel)', marginBottom: '6px' }}>3. ASAN CHECK</div>
                          <div style={{ fontSize: '18px', fontWeight: 400, color: session.verifications[0].asan_clean ? 'var(--color-mint)' : 'var(--color-coral)' }}>
                            {session.verifications[0].asan_clean ? 'CLEAN' : 'FAIL'}
                          </div>
                        </div>

                        <div style={{ background: 'var(--color-charcoal)', border: 'var(--hairline-border)', padding: '16px 18px', borderRadius: 'var(--radius-sm)' }}>
                          <div style={{ fontSize: '11px', color: 'var(--color-steel)', marginBottom: '6px' }}>4. SAST RE-SCAN</div>
                          <div style={{ fontSize: '18px', fontWeight: 400, color: session.verifications[0].sast_recheck_clean ? 'var(--color-mint)' : 'var(--color-coral)' }}>
                            {session.verifications[0].sast_recheck_clean ? 'CLEAN' : 'FAIL'}
                          </div>
                        </div>
                      </div>
                    </div>
                  ) : (
                    <p style={{ color: 'var(--color-steel)', fontSize: '13px', margin: '0 0 20px 0' }}>Verification engine running...</p>
                  )}

                  {/* Executive Report Box */}
                  {projectData && (
                    <div style={{
                      background: 'var(--color-charcoal)',
                      borderRadius: 'var(--radius-cards)',
                      border: '1px solid rgba(59, 130, 246, 0.3)',
                      padding: '20px 24px'
                    }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
                        <div>
                          <div style={{ fontSize: '12px', color: 'var(--color-signal-blue)', marginBottom: '4px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                            <FileText size={16} /> GENERATED EXECUTIVE AUDIT REPORT
                          </div>
                          <h4 style={{ margin: '0 0 4px 0', fontSize: '18px', fontWeight: 400, color: 'var(--color-snow)' }}>
                            VAJRA Executive Security Audit Report
                          </h4>
                          <div style={{ fontSize: '12px', color: 'var(--color-steel)' }}>
                            Saved at: <code style={{ color: 'var(--color-chalk)' }}>D:\VAJRA\workspace\projects\{projectData.project_id}\reports\</code>
                          </div>
                        </div>

                        <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
                          <button
                            type="button"
                            onClick={handleOpenReportModal}
                            className="btn-hover"
                            style={{
                              background: 'var(--color-graphite)',
                              color: 'var(--color-snow)',
                              border: 'var(--hairline-border)',
                              padding: '8px 16px',
                              borderRadius: 'var(--radius-pills)',
                              fontSize: '12px',
                              fontWeight: 500,
                              cursor: 'pointer',
                              display: 'flex',
                              alignItems: 'center',
                              gap: '6px'
                            }}
                          >
                            <Eye size={15} color="var(--color-arc-blue)" /> View Report Modal
                          </button>

                          <a
                            href={getReportViewUrl(projectData.project_id)}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="btn-hover"
                            style={{
                              background: 'var(--color-graphite)',
                              color: 'var(--color-snow)',
                              border: 'var(--hairline-border)',
                              padding: '8px 16px',
                              borderRadius: 'var(--radius-pills)',
                              fontSize: '12px',
                              fontWeight: 500,
                              textDecoration: 'none',
                              display: 'flex',
                              alignItems: 'center',
                              gap: '6px'
                            }}
                          >
                            <ExternalLink size={15} color="var(--color-arc-blue)" /> Open in New Tab
                          </a>

                          <a
                            href={getReportDownloadUrl(projectData.project_id)}
                            download={`VAJRA_Report_${projectData.project_id}.md`}
                            className="btn-hover"
                            style={{
                              background: 'var(--color-bone)',
                              color: 'var(--color-ink)',
                              padding: '8px 18px',
                              borderRadius: 'var(--radius-pills)',
                              fontSize: '12px',
                              fontWeight: 500,
                              textDecoration: 'none',
                              display: 'flex',
                              alignItems: 'center',
                              gap: '6px',
                              boxShadow: 'var(--shadow-primary-pill)'
                            }}
                          >
                            <Download size={15} /> Download Report (.md)
                          </a>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* TAB 2: PATCH & CORRECTED CODE */}
              {activeTab === 'patch' && (
                <div className="animate-fade-in">
                  {actionsLog.length > 0 && actionsLog[0].proposed_patch ? (
                    <div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px', marginBottom: '14px' }}>
                        <div style={{ fontSize: '12px', color: 'var(--color-fog)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                          <Code2 size={16} color="var(--color-arc-blue)" /> SYNTHESIZED PATCH UNIFIED DIFF
                        </div>

                        {projectData && (
                          <div style={{ display: 'flex', gap: '10px' }}>
                            <button
                              type="button"
                              onClick={handleOpenCodeModal}
                              className="btn-hover"
                              style={{
                                background: 'var(--color-charcoal)',
                                color: 'var(--color-snow)',
                                border: 'var(--hairline-border)',
                                padding: '6px 14px',
                                borderRadius: 'var(--radius-pills)',
                                fontSize: '12px',
                                fontWeight: 400,
                                cursor: 'pointer',
                                display: 'flex',
                                alignItems: 'center',
                                gap: '6px'
                              }}
                            >
                              <Eye size={14} color="var(--color-mint)" /> View Corrected Source Code
                            </button>

                            <a
                              href={getCorrectedCodeDownloadUrl(projectData.project_id)}
                              className="btn-hover"
                              style={{
                                background: 'var(--color-charcoal)',
                                color: 'var(--color-snow)',
                                border: 'var(--hairline-border)',
                                padding: '6px 14px',
                                borderRadius: 'var(--radius-pills)',
                                fontSize: '12px',
                                fontWeight: 400,
                                textDecoration: 'none',
                                display: 'flex',
                                alignItems: 'center',
                                gap: '6px'
                              }}
                            >
                              <Download size={14} color="var(--color-mint)" /> Download Corrected File
                            </a>

                            <a
                              href={getPatchDownloadUrl(projectData.project_id)}
                              download={`VAJRA_Patch_${projectData.project_id}.patch`}
                              className="btn-hover"
                              style={{
                                background: 'var(--color-charcoal)',
                                color: 'var(--color-snow)',
                                border: 'var(--hairline-border)',
                                padding: '6px 14px',
                                borderRadius: 'var(--radius-pills)',
                                fontSize: '12px',
                                fontWeight: 400,
                                textDecoration: 'none',
                                display: 'flex',
                                alignItems: 'center',
                                gap: '6px'
                              }}
                            >
                              <Download size={14} color="var(--color-arc-blue)" /> Download Patch (.patch)
                            </a>
                          </div>
                        )}
                      </div>

                      <pre style={{
                        background: 'var(--color-void)',
                        border: 'var(--hairline-border)',
                        padding: '18px 20px',
                        borderRadius: 'var(--radius-sm)',
                        overflowX: 'auto',
                        fontSize: '13px',
                        lineHeight: '1.5',
                        color: 'var(--color-snow)',
                        maxHeight: '380px',
                        margin: 0
                      }}>
                        {actionsLog[0].proposed_patch.split('\n').map((line, i) => {
                          let color = 'var(--color-snow)';
                          if (line.startsWith('+')) color = 'var(--color-mint)';
                          if (line.startsWith('-')) color = 'var(--color-coral)';
                          if (line.startsWith('@@') || line.startsWith('---') || line.startsWith('+++')) color = 'var(--color-steel)';
                          return (
                            <div key={i} style={{ color }}>{line}</div>
                          );
                        })}
                      </pre>
                    </div>
                  ) : (
                    <div style={{ color: 'var(--color-steel)', fontSize: '13px' }}>
                      No synthesized patch available for this run (0 findings discovered or patch not generated).
                    </div>
                  )}
                </div>
              )}

              {/* TAB 3: MISSION AUDIT TRAIL LOG */}
              {activeTab === 'audit' && (
                <div className="animate-fade-in">
                  <div style={{ fontSize: '12px', color: 'var(--color-fog)', marginBottom: '16px' }}>
                    MISSION AUDIT TRAIL LOG EVENTS
                  </div>

                  <div style={{ overflowX: 'auto' }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px', textAlign: 'left', tableLayout: 'fixed' }}>
                      <thead>
                        <tr style={{ borderBottom: 'var(--hairline-border)', color: 'var(--color-steel)' }}>
                          <th style={{ padding: '10px 12px', fontWeight: '400', width: '18%' }}>TIMESTAMP</th>
                          <th style={{ padding: '10px 12px', fontWeight: '400', width: '12%' }}>STAGE</th>
                          <th style={{ padding: '10px 12px', fontWeight: '400', width: '10%' }}>STATUS</th>
                          <th style={{ padding: '10px 12px', fontWeight: '400', width: '48%' }}>DETAILS</th>
                          <th style={{ padding: '10px 12px', fontWeight: '400', width: '12%' }}>AI MODE</th>
                        </tr>
                      </thead>
                      <tbody>
                        {auditTrail.map((log, idx) => (
                          <tr key={idx} className="table-row-hover" style={{ borderBottom: 'var(--hairline-border-subtle)' }}>
                            <td style={{ padding: '10px 12px', color: 'var(--color-steel)', fontFamily: 'ui-monospace, monospace' }}>{log.timestamp}</td>
                            <td style={{ padding: '10px 12px', color: 'var(--color-snow)', fontWeight: '400' }}>{log.stage}</td>
                            <td style={{ padding: '10px 12px', color: log.status === 'PASSED' ? 'var(--color-mint)' : 'var(--color-coral)' }}>
                              {log.status}
                            </td>
                            <td style={{ padding: '10px 12px', color: 'var(--color-chalk)', wordBreak: 'break-word' }}>{log.details}</td>
                            <td style={{ padding: '8px 12px', color: 'var(--color-steel)' }}>{log.ai_mode}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </main>

      {/* ROOT LEVEL MODALS (Outside all parent containers to guarantee 100% viewport fixed rendering) */}
      {showReportModal && (
        <div 
          onClick={(e) => { if (e.target === e.currentTarget) handleCloseModals(); }}
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            width: '100vw',
            height: '100vh',
            background: 'rgba(0, 0, 0, 0.85)',
            backdropFilter: 'blur(12px)',
            zIndex: 99999,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '24px'
          }} className="animate-fade-in"
        >
          <div style={{
            background: 'var(--color-graphite)',
            border: '1px solid rgba(59, 130, 246, 0.4)',
            borderRadius: 'var(--radius-cards)',
            boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.95), 0 0 30px rgba(59, 130, 246, 0.25)',
            width: '100%',
            maxWidth: '960px',
            maxHeight: '85vh',
            display: 'flex',
            flexDirection: 'column',
            overflow: 'hidden'
          }}>
            {/* Modal Header */}
            <div style={{
              padding: '20px 24px',
              borderBottom: 'var(--hairline-border)',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              background: 'var(--color-charcoal)'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <FileText size={20} color="var(--color-signal-blue)" />
                <span style={{ fontSize: '16px', fontWeight: 500, color: 'var(--color-snow)' }}>
                  VAJRA Executive Security Audit Report
                </span>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                {projectData && (
                  <a
                    href={getReportViewUrl(projectData.project_id)}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="btn-hover"
                    style={{
                      background: 'var(--color-graphite)',
                      color: 'var(--color-snow)',
                      border: 'var(--hairline-border)',
                      padding: '6px 14px',
                      borderRadius: 'var(--radius-pills)',
                      fontSize: '12px',
                      fontWeight: 500,
                      textDecoration: 'none',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '6px'
                    }}
                  >
                    <ExternalLink size={14} color="var(--color-arc-blue)" /> Open in New Tab
                  </a>
                )}

                <a
                  href={getReportDownloadUrl(projectData.project_id)}
                  download={`VAJRA_Report_${projectData.project_id}.md`}
                  className="btn-hover"
                  style={{
                    background: 'var(--color-bone)',
                    color: 'var(--color-ink)',
                    padding: '6px 14px',
                    borderRadius: 'var(--radius-pills)',
                    fontSize: '12px',
                    fontWeight: 500,
                    textDecoration: 'none',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px'
                  }}
                >
                  <Download size={14} /> Download .md
                </a>

                <button
                  type="button"
                  onClick={handleCloseModals}
                  style={{
                    background: 'none',
                    border: 'none',
                    color: 'var(--color-fog)',
                    cursor: 'pointer',
                    padding: '4px'
                  }}
                >
                  <X size={20} />
                </button>
              </div>
            </div>

            {/* Modal Body */}
            <div style={{
              padding: '24px',
              overflowY: 'auto',
              flex: 1,
              background: 'var(--color-void)'
            }}>
              {reportLoading ? (
                <div style={{ textAlign: 'center', color: 'var(--color-steel)', padding: '40px 0' }}>
                  Loading Executive Report...
                </div>
              ) : (
                <pre style={{
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-word',
                  fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
                  fontSize: '13px',
                  lineHeight: '1.6',
                  color: 'var(--color-chalk)',
                  margin: 0
                }}>
                  {reportText}
                </pre>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ROOT LEVEL CORRECTED SOURCE CODE MODAL */}
      {showCodeModal && (
        <div 
          onClick={(e) => { if (e.target === e.currentTarget) handleCloseModals(); }}
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            width: '100vw',
            height: '100vh',
            background: 'rgba(0, 0, 0, 0.85)',
            backdropFilter: 'blur(12px)',
            zIndex: 99999,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '24px'
          }} className="animate-fade-in"
        >
          <div style={{
            background: 'var(--color-graphite)',
            border: '1px solid rgba(74, 222, 128, 0.4)',
            borderRadius: 'var(--radius-cards)',
            boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.95), 0 0 30px rgba(74, 222, 128, 0.25)',
            width: '100%',
            maxWidth: '1020px',
            maxHeight: '85vh',
            display: 'flex',
            flexDirection: 'column',
            overflow: 'hidden'
          }}>
            {/* Modal Header */}
            <div style={{
              padding: '20px 24px',
              borderBottom: 'var(--hairline-border)',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              background: 'var(--color-charcoal)'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <FileCode size={20} color="var(--color-mint)" />
                <span style={{ fontSize: '16px', fontWeight: 500, color: 'var(--color-snow)' }}>
                  Target Corrected Source Code: <code style={{ color: 'var(--color-mint)' }}>{codeFilename}</code>
                </span>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <a
                  href={getCorrectedCodeDownloadUrl(projectData.project_id)}
                  className="btn-hover"
                  style={{
                    background: 'var(--color-bone)',
                    color: 'var(--color-ink)',
                    padding: '6px 14px',
                    borderRadius: 'var(--radius-pills)',
                    fontSize: '12px',
                    fontWeight: 500,
                    textDecoration: 'none',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px'
                  }}
                >
                  <Download size={14} /> Download Corrected File
                </a>

                <button
                  type="button"
                  onClick={handleCloseModals}
                  style={{
                    background: 'none',
                    border: 'none',
                    color: 'var(--color-fog)',
                    cursor: 'pointer',
                    padding: '4px'
                  }}
                >
                  <X size={20} />
                </button>
              </div>
            </div>

            {/* Modal Body */}
            <div style={{
              padding: '24px',
              overflowY: 'auto',
              flex: 1,
              background: 'var(--color-void)'
            }}>
              {codeLoading ? (
                <div style={{ textAlign: 'center', color: 'var(--color-steel)', padding: '40px 0' }}>
                  Loading Corrected Source Code...
                </div>
              ) : (
                <pre style={{
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-word',
                  fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
                  fontSize: '13px',
                  lineHeight: '1.6',
                  color: 'var(--color-mint)',
                  margin: 0
                }}>
                  {codeText}
                </pre>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
