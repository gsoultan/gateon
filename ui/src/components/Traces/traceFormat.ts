// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Colours for a trace's status and duration, shared by the Live and History
// tables and the detail view so a 404 looks the same wherever it appears.

export const getStatusColor = (status: string) => {
  const code = parseInt(status);
  if (isNaN(code)) {
    return status === "success" ? "green" : "red";
  }
  if (code >= 200 && code < 300) return "green";
  if (code >= 300 && code < 400) return "blue";
  if (code >= 400 && code < 500) return "orange";
  if (code >= 500) return "red";
  return "gray";
};

export const getDurationColor = (duration: number) => {
  if (duration < 50) return "teal";
  if (duration < 200) return "blue";
  if (duration < 500) return "orange";
  return "red";
};

export const isSuccessStatus = (status: string) =>
  status === "success" || (parseInt(status) >= 200 && parseInt(status) < 400);
