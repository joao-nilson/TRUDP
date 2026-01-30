import time

class CongestionControl:
    def __init__(self):
        self.cwnd = 1.0
        self.ssthresh = 64.0
        self.state = "SLOW_START"

        self.dup_ack_count = 0
        self.last_ack = 0

        self.rtt_samples = []
        self.rtt_min = 0.1
        self.rtt_avg = 0.5
        self.rtt_var = 0.5

        self.timeout_interval = 1.0

    def on_packet_sent(self, seq_num: int = None):
        pass

    def on_ack_received(self, ack_num: int = None, rtt_sample: float = None):
        if rtt_sample is not None:
            self.update_rtt(rtt_sample)

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
            if self.cwnd >= self.ssthresh:
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
        self.timeout_interval = min(self.timeout_interval * 2, 60.0)

    def on_three_duplicate_acks(self):
        self.ssthresh = max(self.cwnd / 2, 2.0)
        self.cwnd = self.ssthresh
        self.state = "FAST_RECOVERY"

    def get_window_size(self) -> int:
        return int(self.cwnd)
    
    def update_rtt(self, sample: float):
        if self.rtt_samples:
            error = sample - self.rtt_avg
            self.rtt_avg = self.rtt_avg + 0.125 * error
            self.rtt_var = 0.75 * self.rtt_var + 0.25 * abs(error)
        else:
            self.rtt_avg = sample
            self.rtt_var = sample / 2

        self.rtt_samples.append(sample)
        if len(self.rtt_samples) > 10:
            self.rtt_samples.pop(0)
            
        if sample < self.rtt_min or self.rtt_min == 0.1:
            self.rtt_min = sample

        self.timeout_interval = self.get_timeout_interval()
            
    def get_timeout_interval(self) -> float:
        timeout = self.rtt_avg + 4 * max(self.rtt_var, 0.01)
        
        timeout = max(timeout, 0.5)   # Mínimo 500ms
        timeout = min(timeout, 30.0)  # Máximo 30s
        
        return timeout
