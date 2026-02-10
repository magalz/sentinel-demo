import streamlit as st
import boto3
from boto3.dynamodb.conditions import Key
import pandas as pd
from datetime import datetime
import json
import time

# --- CONFIGURAÇÕES ---
st.set_page_config(
    page_title="Sentinel AI - DevSecOps Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# Configuração da AWS (Certifique-se que seu PC tem credenciais ou use st.secrets)
AWS_REGION = "us-east-2"
DYNAMODB_TABLE = "SentinelMonitor"

# Conexão com DynamoDB
@st.cache_resource
def get_dynamodb_resource():
    return boto3.resource('dynamodb', region_name=AWS_REGION)

# Função para buscar dados
def get_data():
    dynamodb = get_dynamodb_resource()
    table = dynamodb.Table(DYNAMODB_TABLE)
    try:
        # Pega todos os itens (Scan) - Para produção real, usar Query seria melhor
        response = table.scan()
        items = response.get('Items', [])
        
        # Ordena por data (mais recente primeiro)
        # Tenta converter string para data para ordenar corretamente
        items.sort(key=lambda x: x.get('data_evento', ''), reverse=True)
        return items
    except Exception as e:
        st.error(f"Erro ao conectar no DynamoDB: {e}")
        return []

# Função para formatar data BR
def format_date(date_str):
    try:
        dt = datetime.strptime(date_str.split('.')[0], "%Y-%m-%d %H:%M:%S")
        return dt.strftime("%d/%m/%Y %H:%M")
    except:
        return date_str

# Função para arquivar alerta (Botão Resolver)
def archive_alert(item_id):
    dynamodb = get_dynamodb_resource()
    table = dynamodb.Table(DYNAMODB_TABLE)
    try:
        table.update_item(
            Key={'id_recurso': item_id},
            UpdateExpression="set estado_visualizacao = :s",
            ExpressionAttributeValues={':s': 'ARQUIVADO'}
        )
        st.success(f"Alerta {item_id} arquivado!")
        time.sleep(1)
        st.rerun()
    except Exception as e:
        st.error(f"Erro ao arquivar: {e}")

# --- UI PRINCIPAL ---

st.title("🛡️ Sentinel AI Dashboard")
st.markdown("### Centro de Comando DevSecOps Integrado")
st.markdown("---")

# Sidebar
st.sidebar.header("Navegação")
menu = st.sidebar.radio(
    "Selecione a Visão:",
    ["🚨 Monitoramento Cloud (Runtime)", "💻 Pipeline CI/CD (Buildtime)", "📂 Histórico Arquivado"]
)

st.sidebar.markdown("---")
if st.sidebar.button("🔄 Atualizar Dados"):
    st.rerun()

st.sidebar.info(f"Conectado em: {AWS_REGION}")

# Carregar Dados
all_data = get_data()

# Separar os dados por TIPO
# Cloud = sg, s3, iam (tudo que não é IAC)
# Pipeline = IAC

data_cloud = [x for x in all_data if x.get('tipo') != 'IAC']
data_pipeline = [x for x in all_data if x.get('tipo') == 'IAC']

# --- ABA 1: MONITORAMENTO CLOUD (Runtime) ---
if menu == "🚨 Monitoramento Cloud (Runtime)":
    
    # Filtra apenas os ativos (não arquivados)
    active_alerts = [x for x in data_cloud if x.get('estado_visualizacao') != 'ARQUIVADO']
    
    # KPIs
    kpi1, kpi2, kpi3 = st.columns(3)
    kpi1.metric("Ameaças Ativas", len(active_alerts))
    
    high_risks = len([x for x in active_alerts if x.get('gravidade') == 'ALTA'])
    kpi2.metric("Risco Crítico 🔥", high_risks)
    
    auto_fixed = len([x for x in data_cloud if "removida" in str(x.get('auto_correcao', '')).lower()])
    kpi3.metric("Auto-Corrigidos 🤖", auto_fixed)
    
    st.markdown("### 📡 Alertas em Tempo Real")
    
    if not active_alerts:
        st.success("✅ Nenhum alerta de segurança ativo no momento. A nuvem está segura.")
    else:
        for item in active_alerts:
            with st.container():
                # Cor da borda baseada na gravidade
                severity = item.get('gravidade', 'MEDIA')
                emoji = "🔴" if severity == 'ALTA' else "🟠"
                
                c1, c2 = st.columns([5, 1])
                
                with c1:
                    st.subheader(f"{emoji} {item.get('risco')} ({item.get('tipo').upper()})")
                    st.markdown(f"**Recurso:** `{item.get('id_recurso')}`")
                    st.markdown(f"**Data:** {format_date(item.get('data_evento'))}")
                    st.markdown(f"**Detalhe:** {item.get('json_analise', '{}')}")
                    
                    if item.get('auto_correcao') and item.get('auto_correcao') != "Nenhuma - Monitoramento":
                        st.info(f"🛠️ **Ação da IA:** {item.get('auto_correcao')}")
                
                with c2:
                    st.write("")
                    st.write("")
                    if st.button("Resolver", key=item['id_recurso']):
                        archive_alert(item['id_recurso'])
                
                st.divider()

# --- ABA 2: PIPELINE DEVSECOPS (Buildtime - NOVO) ---
elif menu == "💻 Pipeline CI/CD (Buildtime)":
    st.header("💻 Auditoria de Código (GitHub Actions)")
    st.markdown("Monitoramento preventivo de arquivos de infraestrutura (IaC) antes do deploy.")
    
    if not data_pipeline:
        st.info("Nenhuma execução de pipeline registrada ainda. Dê um Push no GitHub!")
    else:
        # Métricas do Pipeline
        total_scans = len(data_pipeline)
        falhas = len([x for x in data_pipeline if x.get('status_ia') == 'VULNERAVEL'])
        sucessos = total_scans - falhas
        taxa_sucesso = (sucessos / total_scans) * 100 if total_scans > 0 else 0
        
        c1, c2, c3 = st.columns(3)
        c1.metric("Total de Scans", total_scans)
        c2.metric("Aprovações ✅", sucessos)
        c3.metric("Bloqueios de Segurança 🚫", falhas, delta_color="inverse")
        
        st.markdown("---")
        st.markdown("### 📜 Histórico de Scans")
        
        # Lista de Scans
        for item in data_pipeline:
            is_vuln = item.get('status_ia') == 'VULNERAVEL'
            
            # Estilização Visual
            if is_vuln:
                status_color = "red"
                icon = "🚫"
                status_text = "BLOQUEADO"
            else:
                status_color = "green"
                icon = "✅"
                status_text = "APROVADO"
            
            # Extrair nome do arquivo do ID (PR-timestamp-nomedoarquivo.json)
            try:
                nome_arquivo = item.get('id_recurso').split('-')[-1]
            except:
                nome_arquivo = item.get('id_recurso')

            # Card Expansível
            with st.expander(f"{icon} [{format_date(item.get('data_evento'))}] {nome_arquivo} -> {status_text}"):
                
                col_a, col_b = st.columns(2)
                
                with col_a:
                    st.markdown("#### Detalhes da Análise")
                    st.markdown(f"**Arquivo:** `{nome_arquivo}`")
                    st.markdown(f"**Risco Identificado:** {item.get('risco')}")
                    
                    if is_vuln:
                        st.error(f"**Motivo do Bloqueio:** {item.get('detalhe')}")
                    else:
                        st.success("O código passou em todas as verificações de segurança.")
                
                with col_b:
                    st.markdown("#### Metadados")
                    st.text(f"ID Scan: {item.get('id_recurso')}")
                    st.text(f"Origem: GitHub Actions")
                    
                    # Tenta mostrar o JSON da IA formatado
                    try:
                        analise_json = json.loads(item.get('json_analise'))
                        st.json(analise_json)
                    except:
                        st.text("Dados brutos indisponíveis.")

# --- ABA 3: HISTÓRICO (Arquivados) ---
elif menu == "📂 Histórico Arquivado":
    st.header("📂 Histórico de Incidentes Resolvidos")
    
    archived_alerts = [x for x in data_cloud if x.get('estado_visualizacao') == 'ARQUIVADO']
    
    if not archived_alerts:
        st.info("Nenhum alerta arquivado.")
    else:
        # Transforma em DataFrame para tabela bonita
        df = pd.DataFrame(archived_alerts)
        
        # Seleciona colunas úteis
        cols_to_show = ['data_evento', 'tipo', 'risco', 'id_recurso', 'auto_correcao']
        # Garante que as colunas existem (para evitar erro se o json for antigo)
        for col in cols_to_show:
            if col not in df.columns:
                df[col] = '-'
                
        # Renomeia para ficar bonito na tela
        df = df[cols_to_show].rename(columns={
            'data_evento': 'Data',
            'tipo': 'Tipo',
            'risco': 'Risco',
            'id_recurso': 'Recurso',
            'auto_correcao': 'Ação Tomada'
        })
        
        st.dataframe(df, use_container_width=True)