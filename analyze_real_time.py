import matplotlib.pyplot as plt
import numpy as np
from matplotlib.animation import FuncAnimation
from tru_protocol import TRUProtocol
import threading
import time

class RealTimeAnalyzer:
    def __init__(self, protocol: TRUProtocol):
        self.protocol = protocol
        self.fig, self.axes = plt.subplots(2, 2, figsize=(12, 8))
        self.fig.suptitle('Análise em Tempo Real - Protocolo TRUDP')
        
        # Dados para plotagem
        self.times = []
        self.throughputs = []
        self.cwnds = []
        self.rtts = []
        self.packets_in_flight = []
        
        # Configurar gráficos
        self.setup_plots()
        
    def setup_plots(self):
        # Gráfico 1: Throughput
        self.ax1 = self.axes[0, 0]
        self.ax1.set_title('Throughput (Mbps)')
        self.ax1.set_xlabel('Tempo (s)')
        self.ax1.set_ylabel('Throughput')
        self.ax1.grid(True, alpha=0.3)
        self.line1, = self.ax1.plot([], [], 'b-', linewidth=2)
        
        # Gráfico 2: Janela de Congestionamento
        self.ax2 = self.axes[0, 1]
        self.ax2.set_title('Janela de Congestionamento')
        self.ax2.set_xlabel('Tempo (s)')
        self.ax2.set_ylabel('CWND')
        self.ax2.grid(True, alpha=0.3)
        self.line2, = self.ax2.plot([], [], 'g-', linewidth=2)
        
        # Gráfico 3: RTT
        self.ax3 = self.axes[1, 0]
        self.ax3.set_title('RTT (ms)')
        self.ax3.set_xlabel('Tempo (s)')
        self.ax3.set_ylabel('RTT')
        self.ax3.grid(True, alpha=0.3)
        self.line3, = self.ax3.plot([], [], 'r-', linewidth=2)
        
        # Gráfico 4: Pacotes em Voo
        self.ax4 = self.axes[1, 1]
        self.ax4.set_title('Pacotes em Voo')
        self.ax4.set_xlabel('Tempo (s)')
        self.ax4.set_ylabel('Pacotes')
        self.ax4.grid(True, alpha=0.3)
        self.line4, = self.ax4.plot([], [], 'purple', linewidth=2)
        
    def update_data(self):
        current_time = time.time()
        
        # Coletar métricas do protocolo
        stats = self.protocol.get_rtt_stats()
        congestion_stats = self.protocol.get_congestion_stats()
        
        self.times.append(current_time)
        
        # Estimar throughput (simplificado)
        if len(self.times) > 1:
            time_diff = self.times[-1] - self.times[-2]
            if time_diff > 0:
                throughput = len(self.protocol.send_buffer) * 1400 * 8 / time_diff / 1e6  # Mbps
                self.throughputs.append(throughput)
        
        # Coletar outras métricas
        self.cwnds.append(congestion_stats.get('cwnd', 0))
        self.rtts.append(stats.get('avg', 0) * 1000)  # converter para ms
        
        # Pacotes em voo
        in_flight = len(self.protocol.send_buffer)
        self.packets_in_flight.append(in_flight)
        
        max_points = 100
        if len(self.times) > max_points:
            self.times = self.times[-max_points:]
            self.throughputs = self.throughputs[-max_points:]
            self.cwnds = self.cwnds[-max_points:]
            self.rtts = self.rtts[-max_points:]
            self.packets_in_flight = self.packets_in_flight[-max_points:]
    
    def update_plot(self, frame):
        self.update_data()
        
        if len(self.times) > 0:
            rel_times = [t - self.times[0] for t in self.times]
            
            self.line1.set_data(rel_times, self.throughputs)
            self.ax1.relim()
            self.ax1.autoscale_view()
            
            self.line2.set_data(rel_times, self.cwnds)
            self.ax2.relim()
            self.ax2.autoscale_view()
            
            self.line3.set_data(rel_times, self.rtts)
            self.ax3.relim()
            self.ax3.autoscale_view()
            
            self.line4.set_data(rel_times, self.packets_in_flight)
            self.ax4.relim()
            self.ax4.autoscale_view()
        
        return self.line1, self.line2, self.line3, self.line4
    
    def start(self):
        self.ani = FuncAnimation(self.fig, self.update_plot, interval=1000, blit=True)
        plt.tight_layout()
        plt.show()

if __name__ == "__main__":
    protocol = TRUProtocol(is_server=False)
    
    analyzer = RealTimeAnalyzer(protocol)
    
    threading.Thread(target=analyzer.start, daemon=True).start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Análise encerrada")