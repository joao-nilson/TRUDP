import time

class CongestionControl:
    def __init__(self):
        self.cwnd = 1.0
        self.sstresh = 64.0
        self.state = "SLOW_START"

        self.dup_ack_count = 0
        self.last_ack = 0

        self.rtt_samples = []
        self.rtt_min = 0.1
        self.rtt_avg = 0.5
        self.rtt_var = 0.5

    def on_packet_sent(self, seq_num: int = None):
        pass

    def on_ack_received(self, ack_num: int = None):
        if ack_num is not None and ack_num <= self.last_ack:
            self.dup_ack_count += 1
            if self.dup_ack_count >= 3:
                self.on_three_duplicate_acks()
                return
            else:
                self.dup_ack_count = 0
                if ack_num is not None:
                    self.last_ack = ack_num
        
        if self.state == "SLOW_START":
            self.cwnd += 1
            if self.cwnd >= self.sstresh:
                self.state = "CONGESTION_AVOIDANCE"
        elif self.state == "CONGESTION_AVOIDANCE":
            self.cwnd += 1 / self.cwnd
        elif self.state == "FAST_RECOVERY":
            self.cwnd = self.ssthresh
            self.state = "CONGESTION_AVOIDANCE"

    def on_timeout(self):
        self.ssthresh = max(self.cwnd / 2, 2.0)
        self.cwnd = 1.0
        self.state = "SLOW_START"
        self.dup_ack_count = 0

    def on_three_duplicate_acks(self):
        self.sstresh = max(self.cwnd / 2, 2.0)
        self.cwnd = self.sstresh
        self.state = "FAST_RECOVERY"

    def get_window_size(self) -> int:
        return int(self.cwnd)
    
    def update_rtt(self, sample: float):
        self.rtt_samples.append(sample)
        if len(self.rtt_samples) > 10:
            self.rtt_samples.pop(0)
            
        if self.rtt_samples:
            self.rtt_avg = sum(self.rtt_samples) / len(self.rtt_samples)
            self.rtt_min = min(self.rtt_samples)
            
            variances = [(r - self.rtt_avg) ** 2 for r in self.rtt_samples]
            self.rtt_var = sum(variances) / len(variances) if variances else 0.5
            
    def get_timeout_interval(self) -> float:
        """Get timeout interval based on estimated RTT"""
        return max(self.rtt_avg + 4 * max(self.rtt_var, 0.01), 1.0)
