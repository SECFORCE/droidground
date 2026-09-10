// Coalesce startup/recovery requests from all viewers. Normal streams get time
// to provide a keyframe before an encoder reset is necessary.
export const VIDEO_REFRESH_DELAY_MS = 1500;

export class VideoRefreshScheduler {
  private timer?: ReturnType<typeof setTimeout>;
  private refreshing = false;
  private disposed = false;

  constructor(
    private hasWaitingViewer: () => boolean,
    private refresh: () => Promise<void>,
    private onError: (error: unknown) => void,
  ) {}

  request() {
    if (this.disposed || this.timer || this.refreshing) return;
    this.timer = setTimeout(() => {
      this.timer = undefined;
      if (!this.hasWaitingViewer()) return;
      this.refreshing = true;
      void this.refresh()
        .catch(this.onError)
        .finally(() => {
          this.refreshing = false;
        });
    }, VIDEO_REFRESH_DELAY_MS);
    this.timer.unref();
  }

  dispose() {
    this.disposed = true;
    clearTimeout(this.timer);
    this.timer = undefined;
  }
}
