import argparse
import sys
from tru_protocol import TRUConnection, MSS


def main():
    p = argparse.ArgumentParser(description='Cliente TRUDP - envia dados ao servidor')
    p.add_argument('--host', default='127.0.0.1', help='Endereço do servidor')
    p.add_argument('--port', type=int, default=5000, help='Porta do servidor')
    p.add_argument('--packets', type=int, default=10000,
                   help='Número de pacotes a enviar (≥10000 para avaliação). Default: 10000')
    g = p.add_mutually_exclusive_group()
    g.add_argument('--file', metavar='CAMINHO', help='Arquivo a enviar (tamanho define nº de pacotes)')
    g.add_argument('--synthetic', action='store_true',
                   help='Gerar dados sintéticos para preencher o payload')
    args = p.parse_args()

    total_packets = max(args.packets, 10000) if args.packets else 10000
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
        except Exception as e:
            print(f'Erro ao abrir arquivo: {e}', file=sys.stderr)
            sys.exit(1)
    else:
        # Dados sintéticos (preenchimento do payload)
        payload = bytes((i % 256) for i in range(total_bytes))

    conn = TRUConnection(is_server=False)
    print(f'Conectando a {args.host}:{args.port}...')
    if not conn.connect(args.host, args.port):
        print('Falha no handshake.', file=sys.stderr)
        sys.exit(1)
    print('Handshake OK.')
    conn.start()

    if not conn.do_key_exchange_as_client():
        print('Falha no acordo de criptografia.', file=sys.stderr)
        conn.close()
        sys.exit(1)
    print('Criptografia acordada.')

    def progress(sent, total):
        if total > 0 and sent % max(1, total // 20) == 0 or sent == total:
            print(f'  Enviados {sent}/{total} pacotes ({100*sent/total:.1f}%)')

    print(f'Enviando {total_packets} pacotes ({len(payload)} bytes)...')
    ok = conn.send_data(payload, progress_cb=progress)
    conn.close()
    if ok:
        print('Transferência concluída com sucesso.')
    else:
        print('Transferência incompleta ou timeout.', file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()