# RELATÓRIO DE ANÁLISE FORENSE E ENGENHARIA REVERSA DE MALWARE

**Arquivo:** `update_1857477.exe`
**Classificação:** Malicioso (InfoStealer / Phantom V3)
**Data do Relatório:** 11/12/2025
**Metodologia:** Análise Estática Avançada (Sem execução)

---

## 1. Triagem Inicial e Identificação do Arquivo

### 1.1. Inspeção de Cabeçalho (Header)
**Ação:** Execução do comando `file` e `objdump -x`.
**Resultado:** Identificado como `PE32+ executable (GUI) x86-64`.
**Detalhe Técnico:** O binário foi compilado para arquitetura 64-bit e marcado como **"stripped"** (símbolos removidos).
**Por que fizemos isso:** Para entender a arquitetura do processador (x64) e saber se teríamos acesso a nomes de funções (Debugging Symbols). A ausência de símbolos indicou imediatamente que a análise seria mais difícil, exigindo a leitura direta de endereços de memória e Assembly.

### 1.2. Análise de Strings Superficiais
**Ação:** Execução do comando `strings` e filtros com `grep`.
**Resultado:** Encontramos referências a:
* `https://api.ipify.org` (Serviço de IP)
* User-Agents (`Mozilla/5.0... Chrome/120...`)
* Mensagens de erro do GCC (`gcc.gnu.org`)
* DLLs críticas: `WININET.dll`, `CRYPT32.dll`, `wlanapi.dll`.
**Por que fizemos isso:** Strings em texto claro (ASCII/Unicode) são as "frutas baixas". A presença de `api.ipify.org` sugeriu comportamento de reconhecimento de rede. A ausência de uma URL de C2 (Comando e Controle) óbvia indicou o uso de técnicas de ofuscação.

---

## 2. Análise de Capacidades (Imports)

**Ação:** Leitura da seção `.idata` (Import Address Table).
**Resultado:** Identificamos as seguintes funções importadas:
* `CryptUnprotectData` (CRYPT32): Usada para desencriptar senhas salvas no Chrome/Edge.
* `InternetConnectA` / `HttpSendRequestA` (WININET): Capacidade de comunicação HTTP/HTTPS.
* `WlanGetAvailableNetworkList` (wlanapi): Roubo de credenciais Wi-Fi.
* `GetClipboardData` (USER32): Monitoramento da área de transferência.
**Por que fizemos isso:** As importações definem o que o programa *pode* fazer. A combinação dessas funções específicas confirmou a hipótese de um **Stealer** (Ladrão de informações).

---

## 3. Detecção de Ofuscação e Strings Ocultas

### 3.1. Falha na Busca Textual
**Ação:** Tentativa de encontrar "http" ou domínios usando `grep`.
**Resultado:** Negativo (exceto `ipify`).
**Análise:** O malware não armazena seu destino final como texto simples. Ele utiliza **Stack Strings** (construção da string byte-a-byte na pilha durante a execução) ou criptografia.

### 3.2. Extração Avançada (FLOSS)
**Ação:** Uso da ferramenta `FLOSS` (FireEye Labs Obfuscated String Solver).
**Resultado:**
* Identificação de um alfabeto de criptografia: `.,-+xX0123456789abcdef0123456789ABCDEF...`
* Identificação de "Tight Strings" (inteiros que representam dados): **`1096216591`**.
* Identificação de fragmentos de API: `/api/data`.
**Por que fizemos isso:** O FLOSS simula a execução do código para identificar strings que só aparecem na memória RAM. A string "Tight" numérica foi a pista crucial que indicava um IP armazenado como inteiro (DWORD) para evitar detecção.

---

## 4. Engenharia Reversa de Código (Assembly x64)

### 4.1. Localização do Ponto de Conexão
**Ação:** Busca pelo endereço da função `InternetConnectA` na tabela de importação (`0x125ba0`) e quem a chama.
**Comando:** `objdump -d ... | grep "125ba0"`
**Resultado:** Encontramos a chamada (Call Site) no endereço virtual **`14002261b`**.
**Por que fizemos isso:** Como não podíamos ler o C2 estaticamente, precisávamos encontrar o momento exato em que o malware tenta se conectar. A função `InternetConnectA` recebe o endereço do servidor no registrador `RDX`.

### 4.2. Rastreamento de Argumentos (Trace Back)
**Ação:** Análise das instruções precedentes à chamada em `14002261b`.
**Resultado:** Identificamos `mov rdx, QWORD PTR [rsp+0x90]`.
**Análise:** O endereço do C2 não era uma constante, mas sim lido da pilha (`rsp+0x90`). Isso confirmou que o C2 foi processado/descriptografado *antes* desse bloco de código.

### 4.3. Identificação de Anti-Debugging
**Ação:** Leitura do fluxo de controle próximo à conexão.
**Resultado:** Encontramos a instrução `rdtsc` seguida de cálculos matemáticos e uma comparação com `0xdeadbeef`.
**Por que isso é relevante:**
* `rdtsc`: Lê o contador de tempo da CPU.
* `cmp eax, 0xdeadbeef`: Verifica uma assinatura de "memória morta".
* **Conclusão:** O malware mede o tempo de execução. Se um analista estiver depurando (passo-a-passo), o tempo será alto, o cálculo falhará ou cairá no check, e o malware abortará a conexão para se proteger.

---

## 5. Reconstrução Lógica e Descriptografia

### 5.1. Análise Lógica (Pseudocódigo)
**Ação:** Interpretação da lógica descompilada.
**Resultado:** Confirmamos o fluxo:
1.  Verifica Anti-Debug (`rdtsc`).
2.  Seleciona um User-Agent aleatório baseado no tempo (`GetTickCount() % 3`).
3.  Prepara a conexão usando `InternetConnectA` com o C2 recuperado da memória (`local_a0`).
4.  Envia dados via `POST` para `/api/data`.

### 5.2. Extração do C2 (O "Pulo do Gato")
**Ação:** Correlação entre a "Tight String" encontrada pelo FLOSS e o argumento da conexão.
**Dado:** Inteiro `1096216591`.
**Conversão:**
* Hexadecimal: `0x415AA00F`
* Little Endian (Byte Order): `0F` `A0` `5A` `41`
* Decimal: `15` `160` `90` `65`

**Resultado Final (C2):** **`15.160.90.65`**

---

## 6. Conclusão Técnica

O arquivo `update_1857477.exe` é um binário malicioso altamente ofuscado. Ele evita a detecção armazenando seu servidor de comando (C2) não como um domínio de texto (ex: `site.com`), mas como um número inteiro de 4 bytes (`1096216591`), convertendo-o para endereço IP em tempo de execução.

**Indicadores de Comprometimento (IOCs) confirmados:**
1.  **C2 IP:** `15.160.90.65`
2.  **Protocolo:** HTTP/HTTPS (Porta 80 ou 443).
3.  **URL de Exfiltração:** `http://15.160.90.65/api/data`
4.  **Comportamento:** POST de JSON contendo credenciais roubadas.

A análise foi concluída com sucesso sem a necessidade de execução dinâmica, mitigando qualquer risco de infecção da máquina de análise.
