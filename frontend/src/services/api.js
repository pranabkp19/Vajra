import axios from 'axios';

const API_BASE = '/api';

export const uploadProject = async (file) => {
  const formData = new FormData();
  formData.append('file', file);
  const response = await axios.post(`${API_BASE}/projects/upload`, formData, {
    headers: { 'Content-Type': 'multipart/form-data' }
  });
  return response.data;
};

export const startAnalysis = async (projectId) => {
  const response = await axios.post(`${API_BASE}/analysis/start/${projectId}`);
  return response.data;
};

export const getAnalysisStatus = async (projectId) => {
  const response = await axios.get(`${API_BASE}/analysis/status/${projectId}`);
  return response.data;
};

export const getFindings = async (projectId) => {
  const response = await axios.get(`${API_BASE}/findings/${projectId}`);
  return response.data;
};

export const getCompressedEvidence = async (projectId) => {
  const response = await axios.get(`${API_BASE}/findings/${projectId}/compressed-evidence`);
  return response.data;
};

export const getReportStatus = async (projectId) => {
  const response = await axios.get(`${API_BASE}/reports/${projectId}`);
  return response.data;
};

export const getReportView = async (projectId) => {
  const response = await fetch(`${API_BASE}/reports/${projectId}/view`);
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return await response.text();
};

export const getReportViewUrl = (projectId) => {
  return `${API_BASE}/reports/${projectId}/view`;
};

export const getReportDownloadUrl = (projectId) => {
  return `${API_BASE}/reports/${projectId}/download/markdown`;
};

export const getPatchDownloadUrl = (projectId) => {
  return `${API_BASE}/reports/${projectId}/download/patch`;
};

export const getCorrectedCodeView = async (projectId) => {
  const response = await fetch(`${API_BASE}/reports/${projectId}/view/corrected-code`);
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return await response.text();
};

export const getCorrectedCodeDownloadUrl = (projectId) => {
  return `${API_BASE}/reports/${projectId}/download/corrected-code`;
};
