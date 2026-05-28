import { Queue, type JobsOptions } from "bullmq";
import { redis } from "../lib/redis";

export interface GdprErasureJobData {
  userId: string;
  requestId: string;
}

export const gdprErasureJobOptions = {
  attempts: 3,
  backoff: { type: "exponential", delay: 5_000 },
  removeOnComplete: { count: 100 },
  removeOnFail: { count: 100 },
} satisfies JobsOptions;

export const gdprErasureQueue = new Queue("gdpr-erasure", {
  connection: redis,
  defaultJobOptions: gdprErasureJobOptions,
});

const GRACE_PERIOD_MS = 30 * 24 * 60 * 60 * 1000;

/** Enqueue an erasure job to fire after the 30-day grace period. */
export async function enqueueGdprErasure(data: GdprErasureJobData): Promise<void> {
  await gdprErasureQueue.add("erase", data, {
    jobId: `gdpr:${data.userId}`,
    delay: GRACE_PERIOD_MS,
  });
}

/** Remove the pending erasure job (cancel within grace period). */
export async function cancelGdprErasure(userId: string): Promise<void> {
  const job = await gdprErasureQueue.getJob(`gdpr:${userId}`);
  if (job) await job.remove();
}
