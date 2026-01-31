import argparse
import sys
import threading
import time
from tru_protocol import TRUProtocol, MSS
from utils import set_global_loss_probability

def monitor_rtt(conn, interval=5.0):
    import time
    print(f"Iniciando monitoramento de RTT (intervalo: {interval}s)")
    
    try:
        while getattr(conn, 'monitoring_active', True):
            try:
                # Obter estatísticas de RTT
                stats = conn.get_rtt_stats()
                
                print(f"\n[RTT STATS {time.strftime('%H:%M:%S')}]")
                print(f"  Média: {stats['avg']:.6f}s")
                print(f"  Min/Max: {stats['min']:.6f}s / {stats['max']:.6f}s")
                print(f"  Desvio: {stats['dev']:.6f}s")
                print(f"  Timeout: {stats['timeout']:.3f}s")
                print(f"  Amostras: {stats['samples']}")
                
                # Estatísticas de congestionamento
                if hasattr(conn, 'get_congestion_stats'):
                    cstats = conn.get_congestion_stats()
                    print(f"\n[CONGESTION STATS]")
                    print(f"  Estado: {cstats.get('state', 'N/A')}")
                    print(f"  cwnd: {cstats.get('cwnd', 0):.2f}")
                    print(f"  ssthresh: {cstats.get('ssthresh', 0):.2f}")
                    print(f"  Janela: {cstats.get('window', 0)}")
                    print(f"  Dup ACKs: {cstats.get('dup_acks', 0)}")
                
                print("-" * 60)

            except AttributeError as e:
                print(f"[Monitor] Erro: {e}")
                break
            
            time.sleep(interval)
            
    except KeyboardInterrupt:
        print("[Monitor] Monitoramento interrompido pelo usuário")
    finally:
        print("[Monitor] Monitoramento de RTT finalizado")

def main():
    p = argparse.ArgumentParser(description='Cliente TRUDP - envia dados ao servidor')
    p.add_argument('--host', default='127.0.0.1', help='Endereço do servidor')
    p.add_argument('--port', type=int, default=5000, help='Porta do servidor')
    p.add_argument('--packets', type=int, default=10,
                   help='Número de pacotes a enviar (≥10000 para avaliação). Default: 10000')
    p.add_argument('--loss', type=float, default=0.0, metavar='P',
                   help='Probabilidade de perda de pacotes (para testes). Default: 0.0')
    p.add_argument('--monitor', action='store_true',
                   help='Ativar monitoramento de RTT durante a transferência')
    p.add_argument('--monitor-interval', type=float, default=5.0,
                   help='Intervalo em segundos para monitoramento de RTT. Default: 5.0')
    p.add_argument('--no-congestion', action='store_true',
               help='Desativar controle de congestionamento')
    g = p.add_mutually_exclusive_group()
    g.add_argument('--file', metavar='CAMINHO', help='Arquivo a enviar (tamanho define nº de pacotes)')
    g.add_argument('--synthetic', action='store_true',
                   help='Gerar dados sintéticos para preencher o payload')
    args = p.parse_args()

    if args.loss > 0:
        set_global_loss_probability(args.loss)
        print(f"Perda de pacotes configurada: {args.loss*100:.1f}%")

    total_packets = args.packets
    total_bytes = total_packets * MSS

    if args.file:
        try:
            with open(args.file, 'rb') as f:
                payload = f.read()
            if len(payload) < total_bytes:
                payload = payload + (b'\x00' * (total_bytes - len(payload)))
            else:
                payload = payload[:total_bytes]
            total_packets = (len(payload) + MSS - 1) // MSS
            print(f"Lendo arquivo: {len(payload)} bytes, {total_packets} pacotes")
        except Exception as e:
            print(f'Erro ao abrir arquivo: {e}', file=sys.stderr)
            sys.exit(1)
    else:
        # Dados sintéticos (preenchimento do payload)
        payload = bytes((i % 256) for i in range(total_bytes))
        print(f"Gerando {total_packets} pacotes ({total_bytes} bytes)")

    conn = TRUProtocol(is_server=False, 
                   enable_congestion_control=not args.no_congestion)
    conn.start()

    print(f'Conectando a {args.host}:{args.port}...')
    if not conn.connect(args.host, args.port):
        print('Falha no handshake.', file=sys.stderr)
        sys.exit(1)
    print('Handshake OK.')

    if not conn.do_key_exchange_as_client():
        print('Falha no acordo de criptografia.', file=sys.stderr)
        conn.close()
        sys.exit(1)
    print('Criptografia acordada.')

    monitor_thread = None
    if args.monitor:
        try:
            from analyze_real_time import start_analyzer_in_thread
            start_analyzer_in_thread(conn)
        except ImportError:
            print("[Erro] Não foi possível carregar analyze_real_time.py")
        conn.monitoring_active = True
        monitor_thread = threading.Thread(
            target=monitor_rtt, 
            args=(conn, args.monitor_interval),
            daemon=True
        )
        monitor_thread.start()
        print(f"Monitoramento de RTT ativado (intervalo: {args.monitor_interval}s)")

    def progress(sent, total):
        if total > 0 and sent % max(1, total // 20) == 0 or sent == total:
            print(f'  Enviados {sent}/{total} pacotes ({100*sent/total:.1f}%)')

    print(f'Enviando {total_packets} pacotes ({len(payload)} bytes)...')

    try:
        # Adicionar um pequeno delay para garantir que tudo está inicializado
        time.sleep(0.1)
        
        ok = conn.send_data(payload, progress_cb=progress)
        
        if ok:
            # Esperar um pouco para garantir que todos os ACKs cheguem
            time.sleep(1.0)
        
        if hasattr(conn, 'get_rtt_stats'):
            final_stats = conn.get_rtt_stats()
            print("\n" + "="*80)
            print("ESTATÍSTICAS FINAIS DE RTT:")
            print(f"Média RTT: {final_stats['avg']:.3f}s")
            print(f"RTT mínimo: {final_stats['min']:.3f}s")
            print(f"RTT máximo: {final_stats['max']:.3f}s")
            print(f"Desvio padrão: {final_stats['dev']:.3f}s")
            print(f"Timeout final: {final_stats['timeout']:.3f}s")
            print(f"Amostras coletadas: {final_stats['samples']}")
            print("="*80)
            
    except KeyboardInterrupt:
        print("\nTransferência interrompida pelo usuário")
        ok = False
    except Exception as e:
        print(f"\nErro durante a transferência: {e}")
        import traceback
        traceback.print_exc()
        ok = False
    finally:
        if hasattr(conn, 'monitoring_active'):
            conn.monitoring_active = False
        if monitor_thread and monitor_thread.is_alive():
            monitor_thread.join(timeout=2.0)

        conn.close()

        if ok:
            print('Transferência concluída com sucesso.')
        else:
            print('Transferência incompleta ou timeout.', file=sys.stderr)
            sys.exit(1)


if __name__ == '__main__':
    main()