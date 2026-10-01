# Evos Analyzer - AntiDDoS

O Evos Analyzer - AntiDDoS é uma proposta de solução para detectar e mitigar ataques de Negação de Serviço Distribuída (DDoS). A arquitetura prevista combina ingestão de tráfego, análise de padrões, mitigação e monitoramento, com foco em identificar atividades maliciosas e reduzir o impacto sobre o tráfego legítimo.

## Visão geral

O sistema deverá inspecionar continuamente uma cópia do tráfego de rede, comparar a atividade observada com baselines e assinaturas conhecidas e, quando configurado, acionar medidas de mitigação. A captura fora do caminho principal do tráfego é um objetivo da arquitetura para evitar adicionar latência perceptível à comunicação legítima.

## Arquitetura proposta

O fluxo previsto conecta quatro pilares:

1. **Ingestão - Sensor de tráfego:** captura uma cópia do tráfego que chega ao servidor ou roteador para inspeção.
2. **Análise - Motor Analyzer:** compara o tráfego atual com padrões históricos (baselines) e assinaturas de ataques conhecidos para identificar anomalias.
3. **Mitigação - Módulo de resposta:** diante de um ataque detectado, aplica ações configuradas em firewalls, roteadores de borda ou no kernel, como descartar pacotes maliciosos (Drop) ou redirecionar o tráfego para Blackholing ou Scrubbing.
4. **Monitoramento - Painel de controle:** apresenta tráfego, detecções e alertas, além de permitir configurar limites (thresholds).

Em alto nível, o fluxo é: **captura -> análise -> decisão de mitigação -> monitoramento**. A arquitetura deverá permitir integrar os componentes de captura e aplicação de regras aos equipamentos e mecanismos disponíveis em cada ambiente.

## Stack tecnológica recomendada

As tecnologias abaixo são opções para orientar o projeto; a escolha final depende dos requisitos, do ambiente de implantação e de testes de desempenho.

| Componente | Tecnologias recomendadas | Justificativa |
| --- | --- | --- |
| Núcleo de captura e mitigação | eBPF/XDP, C, Rust ou Go | eBPF/XDP permite processar tráfego cedo no caminho de recepção. No modo nativo, o XDP roda no driver da interface antes da pilha de rede do kernel; o descarte por offload na própria NIC depende do suporte do hardware e do driver. C, Rust e Go são opções para componentes de alto desempenho e integrações. |
| Motor de análise (backend) | Go, Rust ou C++ | Adequados para processamento concorrente e análise em memória, incluindo limites de taxa (rate limiting) e detecção de anomalias. |
| Banco de dados e métricas | Prometheus, InfluxDB ou ClickHouse | Opções para métricas e análise de dados de tráfego. A escolha deve considerar volume, retenção e consultas necessárias, como picos de banda e conexões por endereço IP. |
| Dashboard e frontend | React ou Vue.js com TypeScript | Permitem criar interfaces com gráficos atualizados em tempo real, por exemplo usando WebSockets e Apache ECharts. |

A meta de processar milhões de pacotes por segundo (PPS) deve ser validada com benchmarks na plataforma alvo. O desempenho depende também da placa de rede, do driver, do modo XDP, das regras aplicadas e do padrão de tráfego.

## Estado do projeto

Este repositório contém a descrição inicial da arquitetura. A implementação, as dependências e os comandos de execução ainda precisam ser definidos; portanto, os componentes acima representam objetivos de projeto, não funcionalidades disponíveis atualmente.

## Configuração

O painel deverá permitir configurar limites de detecção. Outros parâmetros, como baselines e integrações de mitigação, serão definidos conforme a implementação e os ambientes suportados forem especificados.

## Como contribuir

Contribuições são bem-vindas. Para aprimorar a lógica de detecção, adicionar analisadores ou melhorar os relatórios:

1. Faça um fork do repositório
2. Crie uma branch para sua funcionalidade
3. Implemente suas alterações
4. Adicione ou atualize os testes, quando aplicável
5. Envie um pull request

## Licença

Este projeto é disponibilizado no estado em que se encontra. Adicione uma licença apropriada caso queira publicá-lo ou distribuí-lo.

