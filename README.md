# TRUDP - Transport Reliable UDP

Um protocolo de transporte confiável implementado sobre UDP.

## Objetivos
- Implementar um protocolo confiável sobre UDP
- Controle de congestionamento estilo TCP
- Handshake de 3 vias
- Transferência confiável de arquivos

`# Executar todos os experimentos automaticamente
python run_experiments.py
pip install matplotlib

# 1. Iniciar o servidor
`python server.py [opções]
`
# 2. Executar o cliente
`
python client.py [opções]
`
# 3. opções
`--host ENDEREÇO  Endereço IP do servidor (cliente) ou interface (servidor)
`
`
--port PORTA  Porta para conexão
`
`
--packets N  Número de pacotes a enviar/receber
`
`
--loss P  Probabilidade de perda artificial de pacotes (0.0 a 1.0)
`
`
--monitor	Ativar monitoramento de RTT durante a transferência
`
`
--monitor-interval S	Intervalo em segundos para monitoramento
`
`
--no-congestion	Desativar controle de congestionamento
`
## opções exclusivas do cliente
`
--file CAMINHO	Enviar conteúdo de arquivo binário
`
`
--synthetic	Gerar dados sintéticos automaticamente
`

# opções exclusivas do servidor
`
--output ARQUIVO	Arquivo para salvar dados recebidos
`

# Grafico com congestionamento e sem perda
`python3 client.py --packets 10000 --monitor
python3 server.py --packets 10000 --monitor`

# Grafico sem congestionamento e sem perda
`
python3 client.py --packets 10000 --no-congestion --monitor
`

# Com perdas e sem controle de congestionamento
`
python client.py --packets 1000 --loss 0.05 --no-congestion --monitor
python server.py --packets 1000 --loss 0.05 --no-congestion --monitor`
`
