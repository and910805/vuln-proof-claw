export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly detail: string,
  ) {
    super(detail);
  }
}

export function authorizedHeaders(token: string, initial?: HeadersInit): Headers {
  const headers = new Headers(initial);
  const normalized = token.trim();
  if (normalized) headers.set("Authorization", `Bearer ${normalized}`);
  return headers;
}

export async function apiRequest<T>(
  path: string,
  token: string,
  init: RequestInit = {},
): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: authorizedHeaders(token, init.headers),
  });
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`;
    try {
      const payload = (await response.json()) as { detail?: unknown };
      if (typeof payload.detail === "string") detail = payload.detail;
    } catch {
      // Preserve the safe status fallback when the response is not JSON.
    }
    throw new ApiError(response.status, detail);
  }
  return (await response.json()) as T;
}

export async function downloadApiFile(path: string, token: string, filename: string) {
  const response = await fetch(path, { headers: authorizedHeaders(token) });
  if (!response.ok) throw new ApiError(response.status, `${response.status} ${response.statusText}`);
  const objectUrl = URL.createObjectURL(await response.blob());
  const anchor = document.createElement("a");
  anchor.href = objectUrl;
  anchor.download = filename;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(objectUrl), 0);
}
