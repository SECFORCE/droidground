import Logger from "@shared/logger";
import { QueueJob, JobInfo, JobStatusType } from "@shared/types";

export class FairQueue<UserId extends string> {
  private readonly perUser = new Map<UserId, QueueJob<UserId>[]>();
  private readonly activeUsers: UserId[] = [];
  private nextUserIndex = 0;

  private running = 0;

  constructor(
    private readonly opts: {
      concurrency: number; // 1 => strictly one job running at a time
      maxPerUserQueue: number; // cap buffered jobs per user
      maxTotalQueue: number; // cap total buffered jobs
    },
  ) {
    if (opts.concurrency < 1) throw new Error("concurrency must be >= 1");
  }

  get queuedCount(): number {
    let total = 0;
    for (const q of this.perUser.values()) total += q.length;
    return total;
  }

  enqueue(job: Omit<QueueJob<UserId>, "createdAt">): { ok: true; createdAt: number } | { ok: false; reason: string } {
    if (this.queuedCount >= this.opts.maxTotalQueue) {
      return { ok: false, reason: "Queue is full" };
    }

    const queue = this.perUser.get(job.userId) ?? [];
    if (queue.length >= this.opts.maxPerUserQueue) {
      return { ok: false, reason: "Too many queued jobs for this user" };
    }

    // If this user had no queue yet, add them to the ring
    if (!this.perUser.has(job.userId)) {
      this.perUser.set(job.userId, queue);
      this.activeUsers.push(job.userId);
    }

    const createdAt = Date.now();
    queue.push({ ...job, createdAt: createdAt });

    Logger.info(
      `Job enqueued: ${JSON.stringify({
        jobId: job.id,
        userId: job.userId,
        queued: this.queuedCount,
      })}`,
    );

    this.pump();
    return { ok: true, createdAt };
  }

  private pump() {
    while (this.running < this.opts.concurrency) {
      const job = this.pickNextJob();
      if (!job) return;

      this.running++;
      void this.execute(job);
    }
  }

  private async execute(job: QueueJob<UserId>) {
    const { id, userId } = job;

    Logger.info(
      `Job started: ${JSON.stringify({
        jobId: id,
        userId,
        running: this.running,
      })}`,
    );

    try {
      await job.run(job.createdAt);
      Logger.info(
        `Job completed: ${JSON.stringify({
          jobId: id,
          userId,
        })}`,
      );
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);

      Logger.error(
        `Job failed: ${JSON.stringify({
          jobId: id,
          userId,
          error: message,
        })}`,
      );
    } finally {
      this.running--;
      this.pump();
    }
  }

  /**
   * Fairness rule:
   * - Iterate users in round-robin order.
   * - Take exactly one job from the first user that has pending jobs.
   * - Remove users from the ring when they become empty.
   */
  private pickNextJob(): QueueJob<UserId> | null {
    if (this.activeUsers.length === 0) return null;

    // We will try at most once per active user
    const attempts = this.activeUsers.length;

    for (let i = 0; i < attempts; i++) {
      const userId = this.activeUsers[this.nextUserIndex];
      this.nextUserIndex = (this.nextUserIndex + 1) % this.activeUsers.length;

      const queue = this.perUser.get(userId);
      if (!queue || queue.length === 0) {
        this.removeUser(userId);
        if (this.activeUsers.length === 0) return null;
        this.nextUserIndex %= this.activeUsers.length;
        continue;
      }

      const job = queue.shift()!;

      // If user became empty, clean them up now (keeps ring tidy)
      if (queue.length === 0) {
        this.perUser.delete(userId);
        this.removeUser(userId);
        this.nextUserIndex = this.activeUsers.length ? this.nextUserIndex % this.activeUsers.length : 0;
      }

      return job;
    }

    return null;
  }

  private removeUser(userId: UserId) {
    const index = this.activeUsers.indexOf(userId);
    if (index === -1) return;

    this.activeUsers.splice(index, 1);

    // Keep nextUserIndex pointing to the same "next" logical user
    if (this.activeUsers.length === 0) {
      this.nextUserIndex = 0;
    } else if (index < this.nextUserIndex) {
      this.nextUserIndex--;
    }
  }

  public getQueueStatus(): JobInfo[] {
    return [...this.perUser.values()].flat().map(qj => ({
      id: qj.id,
      packageName: qj.packageName,
      status: JobStatusType.WAITING,
      createdAt: qj.createdAt,
    }));
  }
}
