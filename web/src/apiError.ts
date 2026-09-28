type ValidationIssue = { loc?: unknown; msg?: unknown };

function validationIssueMessage(value: unknown): string | null {
  if (!value || typeof value !== "object") return null;
  const issue = value as ValidationIssue;
  if (typeof issue.msg !== "string" || !issue.msg.trim()) return null;
  const location = Array.isArray(issue.loc)
    ? issue.loc.filter((part) => part !== "body" && (typeof part === "string" || typeof part === "number"))
      .map(String).join(".")
    : "";
  return location ? `${location}: ${issue.msg}` : issue.msg;
}

export function apiErrorMessage(body: unknown, status: number): string {
  const fallback = `Request failed (HTTP ${status}).`;
  if (!body || typeof body !== "object") return fallback;
  const detail = (body as { detail?: unknown }).detail;
  if (typeof detail === "string" && detail.trim()) return detail;
  if (Array.isArray(detail)) {
    const messages = detail.map(validationIssueMessage).filter((message): message is string => !!message);
    if (messages.length) return messages.join("; ");
  }
  const issue = validationIssueMessage(detail);
  return issue ?? fallback;
}
