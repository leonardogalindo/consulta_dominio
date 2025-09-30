#!/bin/bash

# Função para validar se o input é um nome de domínio válido
is_valid_domain() {
  local domain=$1
  # Regex para domínios, incluindo subdomínios e TLDs com mais de 2 caracteres
  local pattern="^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(\.[a-zA-Z]{2,})?$"
  if [[ $domain =~ $pattern ]]; then
    return 0 # Válido
  else
    return 1 # Inválido
  fi
}

# Variável para armazenar o domínio
DOMINIO="$1"

# Verificar se um domínio foi informado
if [ -z "$DOMINIO" ]; then
  echo "Uso: $0 <domínio>"
  exit 1
fi

# Validar o nome de domínio
if ! is_valid_domain "$DOMINIO"; then
  echo "Erro: Nome de domínio inválido."
  exit 1
fi

# Função para extrair informações do WHOIS
get_whois_info() {
  local domain=$1
  local whois_output=$(whois -- "$domain")
  local owner_info=""
  local registration_date=""
  local expiration_date=""
  local abuse_contact=""
  local responsible_contact=""
  local responsible_email=""
  local name_servers=""
  local domain_status=""

  if [ $? -ne 0 ]; then
      echo "Erro ao executar o whois para o domínio."
      return 1
  fi

  # Extrair informações do proprietário
  owner_info=$(echo "$whois_output" | grep -iE '^(Registrant|Owner|Holder|Titular|OrgName|Organization):' | head -n 1 | sed -E 's/^[[:space:]]*(Registrant|Owner|Holder|Titular|OrgName|Organization):[[:space:]]*//i')
  if [ -z "$owner_info" ]; then
    owner_info="Informação do proprietário não encontrada de forma clara."
  fi

  # Extrair data de registro
  registration_date=$(echo "$whois_output" | grep -iE '^(Creation Date|Registration Date|Registered On|created):' | head -n 1 | sed -E 's/^[[:space:]]*(Creation Date|Registration Date|Registered On|created):[[:space:]]*//i')
  if [ -z "$registration_date" ]; then
    registration_date="Não encontrada."
  fi

  # Extrair data de expiração
  expiration_date=$(echo "$whois_output" | grep -iE '^(Expiry Date|Expiration Date|Expires On|expires):' | head -n 1 | sed -E 's/^[[:space:]]*(Expiry Date|Expiration Date|Expires On|expires):[[:space:]]*//i')
  if [ -z "$expiration_date" ]; then
    expiration_date="Não encontrada."
  fi

  # Extrair contato de abuso
  abuse_contact=$(echo "$whois_output" | grep -iE 'abuse|abuse-mailbox|abuse-c|abuse@' | head -n 1)
  if [ -z "$abuse_contact" ]; then
    abuse_contact="Contato de abuso não encontrado."
  fi

  # Extrair Servidores de Nome
  name_servers=$(echo "$whois_output" | grep -iE '^(Name Server|Nserver):' | sed -E 's/^[[:space:]]*(Name Server|Nserver):[[:space:]]*//i' | tr '\n' ' ')
  if [ -z "$name_servers" ]; then
    name_servers="Não encontrados."
  fi

  # Extrair Status do Domínio
  domain_status=$(echo "$whois_output" | grep -iE '^(Status|Domain Status):' | head -n 1 | sed -E 's/^[[:space:]]*(Status|Domain Status):[[:space:]]*//i')
  if [ -z "$domain_status" ]; then
    domain_status="Não determinado."
  fi

  # Extrair Contato Responsável e Email (para .br domínios)
  responsible_contact=$(echo "$whois_output" | grep -iE '^responsible:' | head -n 1 | sed -E 's/^[[:space:]]*responsible:[[:space:]]*//i')
  if [ -z "$responsible_contact" ]; then
    responsible_contact="Não encontrado."
  fi

  responsible_email=$(echo "$whois_output" | grep -iE '^e-mail:' | head -n 1 | sed -E 's/^[[:space:]]*e-mail:[[:space:]]*//i')
  if [ -z "$responsible_email" ]; then
    responsible_email="Não encontrado."
  fi

  echo "Proprietário: $owner_info"
  echo "Data de Registro: $registration_date"
  echo "Data de Expiração: $expiration_date"
  echo "Contato Abuse: $abuse_contact"
  echo "Servidores de Nome: $name_servers"
  echo "Status do Domínio: $domain_status"
  echo "Contato Responsável: $responsible_contact"
  echo "Email Responsável: $responsible_email"
  return 0
}



# Função para realizar consulta DNS e obter hostname
get_dns_info() {
  local domain=$1
  local ip_address=$(dig +short "$domain" A | head -n 1)
  local hostname=""

  echo "Registros A (Endereços IPv4):"
  dig +short "$domain" A
  echo ""

  echo "Registros AAAA (Endereços IPv6):"
  dig +short "$domain" AAAA
  echo ""

  echo "Registros MX (Servidores de E-mail):"
  dig +short "$domain" MX
  echo ""

  echo "Registros NS (Servidores de Nomes):"
  dig +short "$domain" NS
  echo ""

  echo "Registros TXT (Registros de Texto):"
  dig +short "$domain" TXT
  echo ""

  echo "Registros CNAME (Apelidos):"
  dig +short "$domain" CNAME
  echo ""

  echo "Registros SOA (Start of Authority):"
  dig +short "$domain" SOA
  echo ""

  echo "Registros SRV (Service Records):"
  dig +short "$domain" SRV
  echo ""

  echo "Registros CAA (Certification Authority Authorization):"
  dig +short "$domain" CAA
  echo ""

  echo "Registros DS (Delegation Signer):"
  dig +short "$domain" DS
  echo ""

  echo "Registros DNSKEY (DNS Key):"
  dig +short "$domain" DNSKEY
  echo ""

  echo "Registros RRSIG (DNSSEC Signature):"
  dig +short "$domain" RRSIG
  echo ""

  echo "Registros NSEC (Next Secure record):"
  dig +short "$domain" NSEC
  echo ""

  if [ -n "$ip_address" ]; then
    echo "Endereço IP (Entrada A): $ip_address"
    # Tentativa de resolução reversa para obter o hostname
    hostname=$(dig +short -x "$ip_address")
    if [ -n "$hostname" ]; then
      echo "Hostname Associado ao IP: $hostname"
    else
      echo "Não foi possível determinar o hostname associado ao IP: $ip_address"
    fi
  else
    echo "Nenhum endereço IP (Registro A) encontrado para $domain."
  fi
}

# Função para analisar IP e ISP
get_isp_info() {
  local ip_address=$1
  local whois_ip_info=$(whois -- "$ip_address")
  local isp_info=""

  if [ $? -ne 0 ]; then
      echo "Erro ao executar o whois para o IP."
      return 1
  fi

  isp_info=$(echo "$whois_ip_info" | grep -iE '^(owner|OrgName|netname|descr)')
  if [ -n "$isp_info" ]; then
    echo "Informações do ISP:"
    echo "$isp_info"
  else
    echo "Não foi possível determinar o ISP para o IP: $ip_address"
  fi
  return 0
}


# Captura toda a saída em uma variável
OUTPUT=$(
echo "============================================================"
echo "Consulta Detalhada para o Domínio: $DOMINIO"
echo "============================================================"

# --- Consulta WHOIS do Domínio ---
echo -e "
--- Informações do Proprietário (WHOIS) ---"
get_whois_info "$DOMINIO"

# --- Consulta de Zona DNS e Hostname ---
echo -e "
--- Análise da Zona DNS e Hostname ---"
get_dns_info "$DOMINIO"

# --- Análise do IP e ISP ---
echo -e "
--- Análise do IP e Provedor (ISP) ---"
IP_ADDRESS=$(dig +short "$DOMINIO" A | head -n 1)
if [ -n "$IP_ADDRESS" ]; then
  get_isp_info "$IP_ADDRESS"
else
  echo "Nenhum endereço IP (Registro A) encontrado para $DOMINIO para análise de ISP."
fi

echo -e "
============================================================"
echo "Consulta finalizada."
echo "============================================================"
)

# Exibe a saída no console
echo "$OUTPUT"

# Envia a saída por e-mail
exit 0