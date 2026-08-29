import React, { useState } from 'react';
import { Upload, FileCode, AlertTriangle, CheckCircle2, ArrowRight } from 'lucide-react';
import { uploadProject } from '../services/api';

export default function ProjectUpload({ onUploadSuccess }) {
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
    }
  };

  const handleUpload = async (e) => {
    e.preventDefault();
    if (!file) return;
    setLoading(true);
    setError(null);
    try {
      const data = await uploadProject(file);
      onUploadSuccess(data);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to upload project.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="hover-card animate-fade-in" style={{
      background: 'var(--color-graphite)',
      borderRadius: 'var(--radius-cards)',
      border: 'var(--hairline-border)',
      boxShadow: 'var(--card-inset-highlight)',
      padding: 'var(--card-padding)',
      color: 'var(--color-snow)',
      marginBottom: 'var(--section-gap)'
    }}>
      {/* Eyebrow */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        fontSize: '12px',
        fontFamily: 'var(--font-inter)',
        color: 'var(--color-fog)',
        letterSpacing: '-0.015em',
        marginBottom: '12px'
      }}>
        <span className="status-dot-blue"></span>
        TARGET WORKSPACE INITIALIZATION
      </div>

      {/* Whisper-Weight Display Headline */}
      <h2 style={{
        margin: '0 0 12px 0',
        fontSize: '42px',
        lineHeight: '1.2',
        letterSpacing: '-0.021em',
        fontWeight: 400,
        color: 'var(--color-snow)'
      }}>
        Upload C/C++ Target Project
      </h2>

      <p style={{
        fontSize: '14px',
        lineHeight: '1.43',
        letterSpacing: '-0.023em',
        color: 'var(--color-steel)',
        marginTop: 0,
        marginBottom: '28px'
      }}>
        Select a C/C++ source file (<code style={{ color: 'var(--color-snow)', background: 'var(--color-charcoal)', padding: '2px 6px', borderRadius: '4px', border: 'var(--hairline-border-subtle)' }}>.c</code>, <code style={{ color: 'var(--color-snow)', background: 'var(--color-charcoal)', padding: '2px 6px', borderRadius: '4px', border: 'var(--hairline-border-subtle)' }}>.cpp</code>) or archive (<code style={{ color: 'var(--color-snow)', background: 'var(--color-charcoal)', padding: '2px 6px', borderRadius: '4px', border: 'var(--hairline-border-subtle)' }}>.zip</code>, <code style={{ color: 'var(--color-snow)', background: 'var(--color-charcoal)', padding: '2px 6px', borderRadius: '4px', border: 'var(--hairline-border-subtle)' }}>.tar.gz</code>) for automated vulnerability discovery, AI reasoning, and deterministic verification.
      </p>

      <form onSubmit={handleUpload}>
        {/* Dropzone Container with hover effect */}
        <div className="dropzone-hover" style={{
          background: 'var(--color-charcoal)',
          border: 'var(--hairline-border)',
          borderRadius: 'var(--radius-cards)',
          padding: '36px 24px',
          textAlign: 'center',
          marginBottom: '24px',
          cursor: 'pointer'
        }}>
          <FileCode size={36} color="var(--color-fog)" style={{ marginBottom: '12px' }} />
          <div style={{
            fontSize: '12px',
            color: 'var(--color-steel)',
            letterSpacing: '-0.015em',
            marginBottom: '16px'
          }}>
            SELECT OR DRAG C/C++ SOURCE FILE
          </div>
          <input
            type="file"
            onChange={handleFileChange}
            accept=".c,.cpp,.h,.hpp,.zip,.tar.gz"
            style={{
              color: 'var(--color-chalk)',
              fontSize: '13px',
              fontFamily: 'var(--font-inter)',
              cursor: 'pointer'
            }}
          />
          {file && (
            <div style={{
              color: 'var(--color-mint)',
              marginTop: '16px',
              fontSize: '12px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '6px'
            }}>
              <CheckCircle2 size={14} /> Selected: {file.name} ({Math.round(file.size / 1024)} KB)
            </div>
          )}
        </div>

        {error && (
          <div style={{
            background: 'rgba(248, 113, 113, 0.1)',
            border: '0.5px solid var(--color-coral)',
            padding: '12px 16px',
            borderRadius: 'var(--radius-buttons)',
            color: 'var(--color-coral)',
            marginBottom: '24px',
            fontSize: '13px',
            display: 'flex',
            alignItems: 'center',
            gap: '8px'
          }}>
            <AlertTriangle size={16} /> {error}
          </div>
        )}

        {/* Primary Pill Button with hover animation */}
        <button
          type="submit"
          disabled={!file || loading}
          className={file && !loading ? "btn-hover" : ""}
          style={{
            background: file && !loading ? 'var(--color-bone)' : 'var(--color-smoke)',
            color: file && !loading ? 'var(--color-ink)' : 'var(--color-steel)',
            border: 'none',
            padding: '12px 24px',
            borderRadius: 'var(--radius-pills)',
            fontWeight: 500,
            fontSize: '14px',
            letterSpacing: '-0.023em',
            boxShadow: file && !loading ? 'var(--shadow-primary-pill)' : 'none',
            cursor: file && !loading ? 'pointer' : 'not-allowed',
            width: '100%',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '8px'
          }}
        >
          {loading ? 'Initializing Workspace Sandbox...' : (
            <>
              Initialize Analysis Pipeline <ArrowRight size={16} />
            </>
          )}
        </button>
      </form>
    </div>
  );
}
