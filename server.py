import argparse
import random
import sys
from tru_protocol import TRUConnection, set_global_loss_probability


def main():
    p = argparse.ArgumentParser(description='Servidor TRUDP - recebe dados do cliente')
    p.add_argument('--host', default='0.0.0.0', help='Interface de escuta')
    p.add_argument('--port', type=int, default=5000, help='Porta de escuta')
    p.add_argument('--packets', type=int, default=10000,
                   help='Número de pacotes a receber (deve bater com o cliente). Default: 10000')
    p.add_argument('--loss', type=float, default=0.0, metavar='P',
                   help='Probabilidade de descartar cada pacote recebido (0.0 a 1.0). '
                        'Usado para avaliar o controle de congestionamento. Default: 0.0')
    p.add_argument('--output', default='received.bin', metavar='ARQUIVO',
                   help='Arquivo de saída para os dados recebidos. Default: received.bin')
    args = p.parse_args()

    set_global_loss_probability(args.loss)
    loss_p = args.loss
    total_segments = max(args.packets, 10000)

    def loss_filter(seq):
        return random.random() >= loss_p

    conn = TRUConnection(host=args.host, port=args.port, is_server=True, loss_callback=loss_filter)
    print(f'Servidor ouvindo em {args.host}:{args.port}')
    if loss_p > 0:
        print(f'Perda artificial ativa: {loss_p*100:.1f}% dos pacotes podem ser descartados.')

    if not conn.accept():
        print('Falha no handshake.', file=sys.stderr)
        conn.close()
        sys.exit(1)
    print('Handshake OK.')

    conn.do_key_exchange_as_server()
    print('Criptografia acordada (chave enviada ao cliente).')

    def progress(received, total):
        if total > 0 and (received % max(1, total // 20) == 0 or received == total):
            print(f'  Recebidos {received}/{total} pacotes ({100*received/total:.1f}%)')

    print(f'Aguardando {total_segments} pacotes...')
    data = conn.recv_data(total_segments, progress_cb=progress)
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
