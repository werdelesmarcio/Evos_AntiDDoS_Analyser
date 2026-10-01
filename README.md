# Evos AntiDDoS Analyser

Um projeto leve para analisar dados de tráfego anti-DDoS, identificar padrões suspeitos e auxiliar na investigação de abusos ou ataques.

## Visão geral

O objetivo desta ferramenta é coletar e processar dados relacionados a eventos de mitigação de DDoS e apresentar um resumo legível do ocorrido, incluindo:

- atividades suspeitas de endereços IP
- padrões de ataque recorrentes
- picos e anomalias de tráfego
- cronologia dos eventos para investigação
- relatórios em um formato fácil de compartilhar

## Funcionalidades

- Interpretar logs anti-DDoS ou registros de eventos exportados
- Agrupar eventos por origem, destino e intervalo de tempo
- Destacar padrões de tráfego anormais e atividades recorrentes
- Gerar resumos concisos para análise e elaboração de relatórios
- Permitir a inclusão de novas regras de detecção e integrações

## Requisitos

- Python 3.10 ou mais recente
- pip
- opcional: ferramenta para criação de ambientes virtuais

## Instalação

```bash
git clone https://github.com/your-user/Evos_AntiDDoS_Analyser.git
cd Evos_AntiDDoS_Analyser
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# ou .venv\Scripts\activate  # Windows
pip install -r requirements.txt
```

Se o projeto ainda não incluir um arquivo `requirements.txt`, instale diretamente as dependências necessárias conforme elas forem adicionadas.

## Uso

Consulte os comandos disponíveis:

```bash
python main.py --help
```

Exemplo de uso:

```bash
python main.py --input ./data/sample.log --output ./reports/report.json
```

Dependendo da implementação do projeto, você também pode indicar uma pasta com arquivos de log ou um conjunto de dados pré-processado.

## Estrutura do projeto

```text
Evos_AntiDDoS_Analyser/
├── README.md
├── requirements.txt
├── app/
├── data/
├── reports/
├── tests/
└── main.py
```

## Configuração

Valores de configuração, como limites, intervalos de tempo e filtros de origem, geralmente podem ser ajustados nas configurações do projeto ou no módulo de configuração correspondente.

## Como contribuir

Contribuições são bem-vindas. Para aprimorar a lógica de detecção, adicionar analisadores ou melhorar os relatórios:

1. Faça um fork do repositório
2. Crie uma branch para sua funcionalidade
3. Implemente suas alterações
4. Adicione ou atualize os testes, quando aplicável
5. Envie um pull request

## Licença

Este projeto é disponibilizado no estado em que se encontra. Adicione uma licença apropriada caso pretenda publicá-lo ou distribuí-lo publicamente.

## Observações

Este README é intencionalmente genérico, pois o repositório ainda não contém os arquivos do projeto. Atualize os comandos, caminhos e exemplos para corresponderem à implementação real quando os arquivos forem adicionados.
