# Consulta Domínio

Script para consultar informações sobre domínios, incluindo dados de WHOIS, registros de zona DNS e informações do provedor de serviços de internet (ISP) associado ao IP do domínio.

## Funcionalidades

*   **Consulta WHOIS:** Obtém informações do proprietário do domínio, datas de registro e expiração, contato de abuso, servidores de nome (NS), status do domínio e contatos responsáveis.
*   **Análise de Zona DNS:** Realiza consultas para diversos tipos de registros DNS, como A, AAAA, MX, NS, TXT, CNAME, SOA, SRV, CAA, DS, DNSKEY, RRSIG e NSEC. Também tenta resolver o hostname associado ao endereço IP do domínio.
*   **Análise de IP e ISP:** Identifica o endereço IP principal do domínio e, em seguida, consulta o WHOIS para obter detalhes sobre o provedor de serviços de internet (ISP) que hospeda esse IP.

## Como Usar

Para executar o script, forneça o domínio como argumento:

```bash
./consulta.dominio.sh example.com
```

O script exibirá todas as informações coletadas no terminal.
