class CongestionControl:
    def __init__(self):
        self.cwnd = 1.0
        self.sstresh = 64.0
        self.state = "SLOW_START"

    def on_ack_received(self):
        if self.state == "SLOW_START":
            self.cwnd += 1
            if self.cwnd >= self.sstresh:
                self.state = "CONGESTION_AVOIDANCE"
        elif self.state == "CONGESTION_AVOIDANCE":
            self.cwnd += 1 / self.cwnd

    def on_timeout(self):
        self.ssthresh = max(self.cwnd / 2, 2.0)
        self.cwnd = 1.0
        self.state = "SLOW_START"

    def on_three_duplicate_acks(self):
        self.sstresh = max(self.cwnd / 2, 2.0)
        self.cwnd = self.sstresh
        self.state = "CONGESTION_AVOIDANCE"

    def get_window_size(self) -> int:
        return int(self.cwnd)
