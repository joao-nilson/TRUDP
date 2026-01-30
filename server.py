import argparse
import random
import sys
import threading
import time
from tru_protocol import TRUProtocol
from utils import set_global_loss_probability, loss_filter

def monitor_rtt(conn, interval=5.0):
    import time
    
    print(f"Iniciando monitoramento de RTT (intervalo: {interval}s)")
    
    try:
        while getattr(conn, 'monitoring_active', True):
            try:
                # Obter estatísticas de RTT
                stats = conn.get_rtt_stats()
                
                if stats['samples'] > 0:
                    print(f"[RTT-SERVER] Média: {stats['avg']:.3f}s | "
                          f"Mín: {stats['min']:.3f}s | "
                          f"Máx: {stats['max']:.3f}s | "
                          f"Desvio: {stats['dev']:.3f}s | "
                          f"Timeout: {stats['timeout']:.3f}s | "
                          f"Amostras: {stats['samples']}")
                else:
                    print(f"[RTT-SERVER] Aguardando amostras... | "
                          f"Timeout atual: {stats['timeout']:.3f}s")
                
                if hasattr(conn, 'receive_stats'):
                    recv_stats = conn.receive_stats
                    print(f"[RECEPTION] Pacotes recebidos: {recv_stats.get('received', 0)} | "
                          f"Pacotes duplicados: {recv_stats.get('duplicates', 0)} | "
                          f"ACKs enviados: {recv_stats.get('acks_sent', 0)}")
                
                print("-" * 80)
                
            except AttributeError as e:
                print(f"[Monitor-Server] Erro ao obter estatísticas: {e}")
                break
            except Exception as e:
                print(f"[Monitor-Server] Erro inesperado: {e}")
                break
            
            time.sleep(interval)
            
    except KeyboardInterrupt:
        print("[Monitor-Server] Monitoramento interrompido pelo usuário")
    finally:
        print("[Monitor-Server] Monitoramento de RTT finalizado")

def main():
    p = argparse.ArgumentParser(description='Servidor TRUDP - recebe dados do cliente')
    p.add_argument('--host', default='0.0.0.0', help='Interface de escuta')
    p.add_argument('--port', type=int, default=5000, help='Porta de escuta')
    p.add_argument('--packets', type=int, default=10,
                   help='Número de pacotes a receber (deve bater com o cliente). Default: 10000')
    p.add_argument('--loss', type=float, default=0.0, metavar='P',
                   help='Probabilidade de descartar cada pacote recebido (0.0 a 1.0). '
                        'Usado para avaliar o controle de congestionamento. Default: 0.0')
    p.add_argument('--monitor', action='store_true',
                   help='Ativar monitoramento de RTT durante a recepção')
    p.add_argument('--monitor-interval', type=float, default=5.0,
                   help='Intervalo em segundos para monitoramento de RTT. Default: 5.0')
    p.add_argument('--output', default='received.bin', metavar='ARQUIVO',
                   help='Arquivo de saída para os dados recebidos. Default: received.bin')
    args = p.parse_args()

    set_global_loss_probability(args.loss)
    loss_p = args.loss
    total_segments = args.packets

    conn = TRUProtocol(host=args.host, port=args.port, is_server=True, loss_callback=loss_filter)

    conn.receive_stats = {
        'received': 0,
        'duplicates': 0,
        'acks_sent': 0
    }

    print(f'Servidor ouvindo em {args.host}:{args.port}')
    if loss_p > 0:
        print(f'Perda artificial ativa: {loss_p*100:.1f}% dos pacotes podem ser descartados.')

    if not conn.accept():
        print('Falha no handshake.', file=sys.stderr)
        conn.close()
        sys.exit(1)
    print('Handshake OK.')

    if not conn.do_key_exchange_as_server():
        print('Falha no acordo de criptografia.', file=sys.stderr)
        conn.close()
        sys.exit(1)
    print('Criptografia acordada (chave enviada ao cliente).')

    monitor_thread = None
    if args.monitor:
        conn.monitoring_active = True
        monitor_thread = threading.Thread(
            target=monitor_rtt, 
            args=(conn, args.monitor_interval),
            daemon=True
        )
        monitor_thread.start()
        print(f"Monitoramento de RTT ativado (intervalo: {args.monitor_interval}s)")

    def progress(received, total):
        if total > 0 and (received % max(1, total // 20) == 0 or received == total):
            print(f'  Recebidos {received}/{total} pacotes ({100*received/total:.1f}%)')

    print(f'Aguardando {total_segments} pacotes...')

    try:
        data = conn.recv_data(total_segments, progress_cb=progress)

        if hasattr(conn, 'get_rtt_stats'):
            final_stats = conn.get_rtt_stats()
            print("\n" + "="*80)
            print("ESTATÍSTICAS FINAIS DE RTT (SERVIDOR):")
            print(f"Média RTT: {final_stats['avg']:.3f}s")
            print(f"RTT mínimo: {final_stats['min']:.3f}s")
            print(f"RTT máximo: {final_stats['max']:.3f}s")
            print(f"Desvio padrão: {final_stats['dev']:.3f}s")
            print(f"Timeout final: {final_stats['timeout']:.3f}s")
            print(f"Amostras coletadas: {final_stats['samples']}")
            print("="*80)
    except KeyboardInterrupt:
        print("\nRecepção interrompida pelo usuário")
        data = b''
    finally:
        if hasattr(conn, 'monitoring_active'):
            conn.monitoring_active = False
        
        if monitor_thread and monitor_thread.is_alive():
            monitor_thread.join(timeout=2.0)

        conn.close()

    try:
        with open(args.output, 'wb') as f:
            f.write(data)
        print(f'Dados salvos em {args.output} ({len(data)} bytes).')
    except Exception as e:
        print(f'Erro ao salvar: {e}', file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
