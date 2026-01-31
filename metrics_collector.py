import time
import json
import threading
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional
import statistics

@dataclass
class PacketMetric:
    timestamp: float
    seq_num: int
    size: int
    is_retransmission: bool
    rtt: Optional[float] = None
    congestion_window: float = 0
    ssthresh: float = 0
    congestion_state: str = ""

@dataclass
class ThroughputSample:
    timestamp: float
    bytes_sent: int
    bytes_acked: int
    packets_in_flight: int
    estimated_throughput: float = 0  # bytes/segundo

class MetricsCollector:
    def __init__(self, experiment_name: str = "experiment"):
        self.experiment_name = experiment_name
        self.packet_metrics: List[PacketMetric] = []
        self.throughput_samples: List[ThroughputSample] = []
        self.start_time = time.time()
        self.last_sample_time = self.start_time
        self.bytes_sent_since_last = 0
        self.bytes_acked_since_last = 0
        self.lock = threading.Lock()
        
        # Estatísticas acumuladas
        self.total_packets_sent = 0
        self.total_retransmissions = 0
        self.total_bytes_sent = 0
        self.total_bytes_acked = 0
        
    def record_packet_sent(self, seq_num: int, size: int, is_retransmission: bool,
                          congestion_window: float, ssthresh: float, congestion_state: str):
        with self.lock:
            metric = PacketMetric(
                timestamp=time.time() - self.start_time,
                seq_num=seq_num,
                size=size,
                is_retransmission=is_retransmission,
                congestion_window=congestion_window,
                ssthresh=ssthresh,
                congestion_state=congestion_state
            )
            self.packet_metrics.append(metric)
            
            self.total_packets_sent += 1
            self.total_bytes_sent += size
            self.bytes_sent_since_last += size
            
            if is_retransmission:
                self.total_retransmissions += 1
    
    def record_ack_received(self, seq_num: int, rtt: float):
        with self.lock:
            # Encontrar o pacote correspondente (pode não estar na ordem)
            for metric in reversed(self.packet_metrics):
                if metric.seq_num == seq_num and metric.rtt is None:
                    metric.rtt = rtt
                    self.total_bytes_acked += metric.size
                    self.bytes_acked_since_last += metric.size
                    break
    
    def sample_throughput(self, packets_in_flight: int):
        current_time = time.time() - self.start_time
        time_delta = current_time - self.last_sample_time
        
        if time_delta > 0.1:  # Amostrar a cada 100ms
            throughput = self.bytes_acked_since_last / time_delta if time_delta > 0 else 0
            
            sample = ThroughputSample(
                timestamp=current_time,
                bytes_sent=self.bytes_sent_since_last,
                bytes_acked=self.bytes_acked_since_last,
                packets_in_flight=packets_in_flight,
                estimated_throughput=throughput
            )
            self.throughput_samples.append(sample)
            
            # Resetar contadores
            self.bytes_sent_since_last = 0
            self.bytes_acked_since_last = 0
            self.last_sample_time = current_time
    
    def get_summary_stats(self) -> Dict:
        with self.lock:
            # Calcular estatísticas de RTT
            rtts = [m.rtt for m in self.packet_metrics if m.rtt is not None]
            
            if rtts:
                avg_rtt = statistics.mean(rtts)
                min_rtt = min(rtts)
                max_rtt = max(rtts)
                std_rtt = statistics.stdev(rtts) if len(rtts) > 1 else 0
            else:
                avg_rtt = min_rtt = max_rtt = std_rtt = 0
            
            # Calcular perda de pacotes
            total_packets = len(self.packet_metrics)
            loss_rate = self.total_retransmissions / total_packets if total_packets > 0 else 0
            
            # Calcular throughput médio
            if self.throughput_samples:
                throughputs = [s.estimated_throughput for s in self.throughput_samples if s.estimated_throughput > 0]
                avg_throughput = statistics.mean(throughputs) if throughputs else 0
                max_throughput = max(throughputs) if throughputs else 0
            else:
                avg_throughput = max_throughput = 0
            
            return {
                "experiment_name": self.experiment_name,
                "total_packets_sent": total_packets,
                "total_retransmissions": self.total_retransmissions,
                "loss_rate": loss_rate,
                "total_bytes_sent": self.total_bytes_sent,
                "total_bytes_acked": self.total_bytes_acked,
                "avg_rtt_seconds": avg_rtt,
                "min_rtt_seconds": min_rtt,
                "max_rtt_seconds": max_rtt,
                "std_rtt_seconds": std_rtt,
                "avg_throughput_bps": avg_throughput * 8,  # Converter para bits/segundo
                "max_throughput_bps": max_throughput * 8,
                "duration_seconds": time.time() - self.start_time
            }
    
    def save_to_file(self, filename: str = None):
        if filename is None:
            filename = f"{self.experiment_name}_metrics.json"
        
        data = {
            "summary": self.get_summary_stats(),
            "packet_metrics": [asdict(m) for m in self.packet_metrics],
            "throughput_samples": [asdict(s) for s in self.throughput_samples]
        }
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"Métricas salvas em {filename}")
        return filename