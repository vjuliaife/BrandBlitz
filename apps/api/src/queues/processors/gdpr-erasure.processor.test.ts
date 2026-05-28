import { describe, expect, it, vi, beforeEach } from "vitest";

// ── mocks ────────────────────────────────────────────────────────────────────

const mockFindPendingErasureRequest = vi.fn();
const mockAnonymizeUser = vi.fn();
const mockMarkErasureExecuted = vi.fn();
const mockRevokeAllUserRefreshTokens = vi.fn();

vi.mock("../../db/queries/gdpr", () => ({
  findPendingErasureRequest: mockFindPendingErasureRequest,
  anonymizeUser: mockAnonymizeUser,
  markErasureExecuted: mockMarkErasureExecuted,
}));

vi.mock("../../lib/tokens", () => ({
  revokeAllUserRefreshTokens: mockRevokeAllUserRefreshTokens,
}));

vi.mock("../../lib/redis", () => ({
  redis: {},
}));

vi.mock("../../lib/logger", () => ({
  logger: { info: vi.fn(), error: vi.fn(), warn: vi.fn() },
}));

import { processGdprErasureJob } from "./gdpr-erasure.processor";

function makeJob(data: { userId: string; requestId: string }) {
  return { id: "job-1", data } as any;
}

// ── tests ────────────────────────────────────────────────────────────────────

describe("processGdprErasureJob", () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it("anonymises user, revokes tokens and marks request executed when request is pending", async () => {
    const userId = "user-abc";
    const requestId = "req-abc";
    mockFindPendingErasureRequest.mockResolvedValueOnce({ id: requestId, user_id: userId });
    mockAnonymizeUser.mockResolvedValueOnce(undefined);
    mockRevokeAllUserRefreshTokens.mockResolvedValueOnce(undefined);
    mockMarkErasureExecuted.mockResolvedValueOnce(undefined);

    await processGdprErasureJob(makeJob({ userId, requestId }));

    expect(mockAnonymizeUser).toHaveBeenCalledWith(userId);
    expect(mockRevokeAllUserRefreshTokens).toHaveBeenCalledWith(userId);
    expect(mockMarkErasureExecuted).toHaveBeenCalledWith(requestId);
  });

  it("skips anonymisation when request is cancelled (no pending request found)", async () => {
    mockFindPendingErasureRequest.mockResolvedValueOnce(null);

    await processGdprErasureJob(makeJob({ userId: "user-xyz", requestId: "req-xyz" }));

    expect(mockAnonymizeUser).not.toHaveBeenCalled();
    expect(mockRevokeAllUserRefreshTokens).not.toHaveBeenCalled();
    expect(mockMarkErasureExecuted).not.toHaveBeenCalled();
  });

  it("skips when a newer request supersedes the job's requestId", async () => {
    mockFindPendingErasureRequest.mockResolvedValueOnce({
      id: "req-newer",
      user_id: "user-abc",
    });

    await processGdprErasureJob(makeJob({ userId: "user-abc", requestId: "req-old" }));

    expect(mockAnonymizeUser).not.toHaveBeenCalled();
  });

  it("is idempotent: skips when no pending request exists (already executed)", async () => {
    mockFindPendingErasureRequest.mockResolvedValueOnce(null);

    await processGdprErasureJob(makeJob({ userId: "user-done", requestId: "req-done" }));

    expect(mockAnonymizeUser).not.toHaveBeenCalled();
  });
});
