import json
import boto3
import os
import urllib.request
import urllib.error
from datetime import datetime
from botocore.exceptions import ClientError

# --- CONFIGURAÇÕES ---
DYNAMODB_TABLE = os.environ.get('DYNAMODB_TABLE', 'SentinelMonitor')
GOOGLE_API_KEY = os.environ.get('GOOGLE_API_KEY', '')

# Clientes AWS
ec2_client = boto3.client('ec2')
s3_client = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(DYNAMODB_TABLE)

def get_sg_config(group_id):
    try:
        response = ec2_client.describe_security_groups(GroupIds=[group_id])
        return response['SecurityGroups'][0]
    except ClientError as e:
        if e.response['Error']['Code'] == 'InvalidGroup.NotFound':
            return None
        return {"id": group_id, "info": f"Erro Boto3: {e}"}
    except Exception as e:
        return {"id": group_id, "info": f"Erro desconhecido: {e}"}

def get_s3_config(bucket_name):
    config = {"bucketName": bucket_name}
    try:
        # Verifica se o bucket existe primeiro
        s3_client.head_bucket(Bucket=bucket_name)
        policy = s3_client.get_bucket_policy(Bucket=bucket_name)
        config['policy'] = json.loads(policy['Policy'])
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == '404' or error_code == 'NoSuchBucket':
            return None
        config['policy'] = f"Sem política ou erro: {e}"
    except Exception as e:
        config['policy'] = f"Sem política ou erro: {e}"
    return config

def ask_gemini(resource_data):
    """Envia qualquer JSON para o Gemini analisar"""
    if not GOOGLE_API_KEY:
        return {"status": "ERRO", "risco": "Sem API Key"}

    prompt = f"""
    Atue como Auditor DevSecOps Sênior. Analise o JSON de infraestrutura AWS abaixo.
    Identifique riscos baseados em princípios de Menor Privilégio e Melhores Práticas (CIS/AWS).
    
    JSON PARA ANÁLISE:
    {json.dumps(resource_data)}

    Responda ESTRITAMENTE em formato JSON (sem markdown):
    {{
        "status": "SEGURO" ou "VULNERAVEL",
        "risco": "Explicação curta do risco",
        "gravidade": "ALTA, MEDIA ou BAIXA",
        "detalhe": "Detalhe técnico",
        "auto_correcao": "Sugestão de correção"
    }}
    """
    
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={GOOGLE_API_KEY}"
    body = {"contents": [{"parts": [{"text": prompt}]}]}
    
    try:
        req = urllib.request.Request(url, data=json.dumps(body).encode('utf-8'), headers={"Content-Type": "application/json"}, method='POST')
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode())
            text = result['candidates'][0]['content']['parts'][0]['text']
            text = text.replace("```json", "").replace("```", "").strip()
            return json.loads(text)
    except Exception as e:
        print(f"Erro Gemini: {e}")
        return {"status": "ERRO_IA", "risco": "Falha na análise", "gravidade": "BAIXA"}

# --- FUNÇÕES DE AUTO-REMEDIAÇÃO ---

def auto_remediate_s3(bucket_name):
    """Limpa e deleta um bucket S3 vulnerável."""
    print(f"🛠️ [AUTO-REMEDIAÇÃO] Iniciando exclusão do bucket comprometido: {bucket_name}")
    try:
        # Para deletar um bucket, ele precisa estar vazio.
        # Paginação para deletar todos os objetos
        paginator = s3_client.get_paginator('list_object_versions')
        for page in paginator.paginate(Bucket=bucket_name):
            delete_keys = []
            for version in page.get('Versions', []):
                delete_keys.append({'Key': version['Key'], 'VersionId': version['VersionId']})
            for marker in page.get('DeleteMarkers', []):
                delete_keys.append({'Key': marker['Key'], 'VersionId': marker['VersionId']})
                
            if delete_keys:
                s3_client.delete_objects(Bucket=bucket_name, Delete={'Objects': delete_keys})
                print(f"   Limpados {len(delete_keys)} objetos/versões.")

        # Deletar o bucket em si
        s3_client.delete_bucket(Bucket=bucket_name)
        msg = f"Bucket {bucket_name} e todo seu conteúdo foram excluídos com sucesso."
        print(f"✅ {msg}")
        return {"status": "SUCESSO", "acao": "Exclusão de Bucket S3", "detalhe": msg}
        
    except ClientError as e:
        if e.response['Error']['Code'] in ('NoSuchBucket', '404'):
            msg = "Bucket já havia sido excluído em evento paralelo."
            return {"status": "IGNORAR", "acao": "Exclusão S3", "detalhe": msg}
            
        msg = f"Falha ao remediar bucket {bucket_name}: {e}"
        print(f"❌ {msg}")
        return {"status": "FALHO", "acao": "Tentativa de exclusão de Bucket S3", "detalhe": msg}

def parse_cloudtrail_ip_permissions(cloudtrail_items):
    """Converte do formato camelCase do CloudTrail para o PascalCase exigido pelo Boto3."""
    boto3_perms = []
    for item in cloudtrail_items:
        perm = {}
        if 'ipProtocol' in item: perm['IpProtocol'] = item['ipProtocol']
        if 'fromPort' in item: perm['FromPort'] = item['fromPort']
        if 'toPort' in item: perm['ToPort'] = item['toPort']
        
        # Ranges IPv4
        if 'ipRanges' in item and 'items' in item['ipRanges']:
            perm['IpRanges'] = [{'CidrIp': r['cidrIp']} for r in item['ipRanges']['items'] if 'cidrIp' in r]
            
        # Ranges IPv6
        if 'ipv6Ranges' in item and 'items' in item['ipv6Ranges']:
            perm['Ipv6Ranges'] = [{'CidrIpv6': r['cidrIpv6']} for r in item['ipv6Ranges']['items'] if 'cidrIpv6' in r]
            
        # Grupos de Segurança
        if 'groups' in item and 'items' in item['groups']:
            perm['UserIdGroupPairs'] = [{'GroupId': g['groupId']} for g in item['groups']['items'] if 'groupId' in g]
            
        boto3_perms.append(perm)
    return boto3_perms

def auto_remediate_ec2(group_id, event_detail):
    """Reverte a regra adicionada causou a vulnerabilidade, ou limpa acessos irrestritos globais em caso de falha de identificação."""
    print(f"🛠️ [AUTO-REMEDIAÇÃO] Investigando Security Group: {group_id}")
    try:
        # Pega a regra exata que foi adicionada a partir do evento do CloudTrail
        request_params = event_detail.get('requestParameters', {})
        ip_permissions_camel = request_params.get('ipPermissions', {}).get('items', [])
        
        regras_para_remover = []
        if ip_permissions_camel:
            # Converte as regras do evento para o formato que o Boto3 aceita
            regras_para_remover = parse_cloudtrail_ip_permissions(ip_permissions_camel)
        else:
            # FALLBACK: Se o evento for apenas CreateSecurityGroup (sem payload de regra),
            # mas a IA viu a regra no estado Boto3, nós varremos e usamos as regras de 0.0.0.0/0
            sg_info = get_sg_config(group_id)
            if sg_info and "IpPermissions" in sg_info:
                for perm in sg_info['IpPermissions']:
                    if not isinstance(perm, dict): continue
                    for ip_range in perm.get('IpRanges', []):
                        if isinstance(ip_range, dict) and ip_range.get('CidrIp') == '0.0.0.0/0':
                            if perm not in regras_para_remover: regras_para_remover.append(perm)
                    for ipv6_range in perm.get('Ipv6Ranges', []):
                        if isinstance(ipv6_range, dict) and ipv6_range.get('CidrIpv6') == '::/0':
                            if perm not in regras_para_remover: regras_para_remover.append(perm)
                            
        if not regras_para_remover:
            msg = "Não foi possível identificar a regra exata no evento e não há regras 0.0.0.0/0 para limpar."
            print(f"⚠️ {msg}")
            return {"status": "PARCIAL", "acao": "Revogação de SG ignorada", "detalhe": msg}
            
        # Revoga as regras perigosas
        ec2_client.revoke_security_group_ingress(
            GroupId=group_id,
            IpPermissions=regras_para_remover
        )
        msg_extra = ""
        # Verifica se o grupo ficou vazio e o deleta
        try:
            sg_info = get_sg_config(group_id)
            if sg_info and not sg_info.get('IpPermissions') and group_id != 'default':
                ec2_client.delete_security_group(GroupId=group_id)
                msg_extra = " O Security Group ficou vazio de regras inbound e foi excluído."
        except Exception as e:
            print(f"Aviso: Não foi possível excluir grupo potencialmente vazio: {e}")
            
        msg = f"Foram revogadas {len(regras_para_remover)} regra(s).{msg_extra}"
        print(f"✅ {msg}")
        return {"status": "SUCESSO", "acao": "Revogação de Regra Inbound", "detalhe": msg}

    except ClientError as e:
        if e.response['Error']['Code'] == 'InvalidGroup.NotFound':
            msg = "Grupo de Segurança já havia sido excluído em evento paralelo."
            return {"status": "IGNORAR", "acao": "Revogação Inbound", "detalhe": msg}
            
        msg = f"Falha ao revogar regra de {group_id}: {e}"
        print(f"❌ {msg}")
        return {"status": "FALHO", "acao": "Tentativa de revogação inbound", "detalhe": msg}
    except Exception as e:
        msg = f"Erro lógico ao processar regras de {group_id}: {e}"
        print(f"❌ {msg}")
        return {"status": "FALHO", "acao": "Processamento de regras", "detalhe": msg}

def lambda_handler(event, context):
    print("🛡️ SENTINEL AI: Iniciando Auditoria Universal...")
    
    detail = event.get('detail', {})
    event_source = detail.get('eventSource', '').split('.')[0].upper() # Ex: RDS, IAM, S3
    event_name = detail.get('eventName', '')
    
    # --- 1. EXTRAÇÃO UNIVERSAL DE ID ---
    # Tenta pegar de vários lugares comuns em eventos CloudTrail
    req_params = detail.get('requestParameters') or {}
    resp_elements = detail.get('responseElements') or {}
    
    # Lista de chaves possíveis para IDs de recursos
    possible_keys = ['groupId', 'bucketName', 'userName', 'dbInstanceIdentifier', 'resourceId', 'functionName', 'policyArn']
    resource_id = "Desconhecido"

    # Busca nas listas de recursos do EventBridge primeiro
    if event.get('resources'):
        resource_id = event['resources'][0].split('/')[-1]
    else:
        # Busca recursiva nos parâmetros da requisição ou resposta
        combined = {**req_params, **resp_elements}
        for key in possible_keys:
            if key in combined:
                resource_id = combined[key]
                break

    print(f"🔍 Evento: {event_source}:{event_name} | Recurso: {resource_id}")

    # --- 2. COLETA DE DADOS (HÍBRIDA) ---
    # Se conhecemos o serviço, buscamos dados extras. Se não, mandamos o log do evento.
    if event_source == 'S3' and resource_id != "Desconhecido":
        data_to_analyze = get_s3_config(resource_id)
    elif event_source == 'EC2' and 'SecurityGroup' in event_name:
        data_to_analyze = get_sg_config(resource_id)
    else:
        # LOG GENÉRICO: Manda o detalhe do evento para a IA extrair o erro
        print(f"⚠️ Serviço {event_source} não possui coletor específico. Enviando log bruto.")
        data_to_analyze = detail

    if data_to_analyze is None:
        msg = f"🛑 Recurso {resource_id} não encontrado (já deletado). Abortando auditoria."
        print(msg)
        return {"statusCode": 200, "body": msg}

# --- 3. ANÁLISE E PERSISTÊNCIA ---
    analysis = ask_gemini(data_to_analyze)
    
    # Adicionamos logs para você ver no console da AWS o que a IA pensou
    print(f"🧠 ANÁLISE COMPLETA DA IA: {json.dumps(analysis, indent=2)}")
    
    remediation_result = "Monitoramento ativo."
    
    if analysis.get('status') == 'VULNERAVEL':
        print("🚨 VULNERABILIDADE DETECTADA! Iniciando Auto-Remediação...")
        
        # --- A AÇÃO DE AUTO-REMEDIAÇÃO ACONTECE AQUI ---
        if event_source == 'S3':
            rem_resp = auto_remediate_s3(resource_id)
            if rem_resp.get("status") == "IGNORAR":
                print(f"🛑 Cancelando gravação no DynamoDB: {rem_resp.get('detalhe')}")
                return {"statusCode": 200, "body": rem_resp.get('detalhe')}
            remediation_result = f"Remediado: {rem_resp['detalhe']}"
        elif event_source == 'EC2' and 'SecurityGroup' in event_name:
            rem_resp = auto_remediate_ec2(resource_id, detail)
            if rem_resp.get("status") == "IGNORAR":
                print(f"🛑 Cancelando gravação no DynamoDB: {rem_resp.get('detalhe')}")
                return {"statusCode": 200, "body": rem_resp.get('detalhe')}
            remediation_result = f"Remediado: {rem_resp['detalhe']}"
        else:
            remediation_result = "Nenhum script de remediação para esse serviço. Ação manual necessária."
        
        try:
            # Montamos o item com TUDO o que o Dashboard espera ver
            item = {
                'id_recurso': f"{resource_id}-{datetime.now().strftime('%H%M%S')}",
                'data_evento': str(datetime.now()),
                'tipo': event_source if event_source != 'EC2' else 'SG',
                'status_ia': 'VULNERAVEL',
                'risco': analysis.get('risco', 'Risco não especificado'),
                'gravidade': analysis.get('gravidade', 'MEDIA'),
                'detalhe': analysis.get('detalhe', 'Sem detalhes técnicos'),
                'auto_correcao': remediation_result,
                'json_analise': json.dumps({"analise_ia": analysis, "resultado_remediacao": remediation_result})
            }
            
            table.put_item(Item=item)
            print("✅ Gravado com sucesso no DynamoDB.")
            
        except Exception as e:
            print(f"❌ Erro ao gravar no DynamoDB: {e}")

    # --- 4. RETORNO ORGANIZADO (Para o log de Teste) ---
    return {
        "statusCode": 200,
        "body": {
            "recurso_auditado": resource_id,
            "veredito_ia": analysis.get('status'),
            "resumo_critico": analysis # Retorna o JSON completo da análise aqui
        }
    }