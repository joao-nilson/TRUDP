# TRUDP - Transport Reliable UDP

Um protocolo de transporte confiável implementado sobre UDP.

## Objetivos
- Implementar um protocolo confiável sobre UDP
- Controle de congestionamento estilo TCP
- Handshake de 3 vias
- Transferência confiável de arquivos

`# Executar todos os experimentos automaticamente
python run_experiments.py

# Ou executar experimentos individuais
python client.py --packets 1000 --loss 0.0 --monitor
python server.py --packets 1000 --loss 0.0 --monitor

# Com perdas e sem controle de congestionamento
python client.py --packets 1000 --loss 0.05 --no-congestion --monitor
python server.py --packets 1000 --loss 0.05 --no-congestion --monitor`