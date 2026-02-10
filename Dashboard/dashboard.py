import streamlit as st
import boto3
import pandas as pd
import json
import time
from datetime import datetime, timedelta
from boto3.dynamodb.conditions import Attr
from botocore.config import Config  # <--- IMPORTANTE PARA O TIMEOUT
from streamlit_autorefresh import st_autorefresh

# --- 1. CONFIGURAÇÃO DA PÁGINA ---
st.set_page_config(
    page_title="Sentinel AI - Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# --- 2. REFRESH AUTOMÁTICO ---
# Intervalo de 10 segundos para perceber rápido a queda da net
st_autorefresh(interval=10 * 1000, key="data_refresh")

# --- 3. CONFIGURAÇÕES AWS ---
TABLE_NAME = 'SentinelMonitor'
REGION = 'us-east-2'

# Configuração de timeout curto para não travar a tela
FAST_TIMEOUT_CONFIG = Config(
    connect_timeout=2, 
    read_timeout=2, 
    retries={'max_attempts': 0}
)

# --- 4. FUNÇÕES ---

def check_aws_connection():
    """Ping rápido (2s) na AWS para testar se o sistema está ONLINE"""
    try:
        # Usa o config de timeout rápido
        client = boto3.client('sts', region_name=REGION, config=FAST_TIMEOUT_CONFIG)
        client.get_caller_identity()
        return True, "ONLINE"
    except Exception:
        # Qualquer erro (sem net, timeout) retorna OFFLINE
        return False, "OFFLINE"

def get_db_resource():
    """Retorna o recurso DynamoDB com configuração segura"""
    return boto3.resource('dynamodb', region_name=REGION, config=FAST_TIMEOUT_CONFIG)

def formatar_data_br(data_str):
    """Converte string UTC para Horário de Brasília (BRT)"""
    if not data_str: return "Data desconhecida"
    try:
        dt_obj = datetime.fromisoformat(str(data_str))
        dt_br = dt_obj - timedelta(hours=3)
        return dt_br.strftime("%d/%m/%Y %H:%M")
    except ValueError:
        return data_str

def get_alerts(is_online):
    """Busca alertas APENAS se estiver online"""
    if not is_online:
        return [] # Se offline, retorna lista vazia sem tentar conectar
        
    try:
        dynamodb = get_db_resource()
        table = dynamodb.Table(TABLE_NAME)
        response = table.scan()
        items = response.get('Items', [])
        items.sort(key=lambda x: x.get('data_evento', ''), reverse=True)
        return items
    except Exception as e:
        # Loga no console do servidor, mas não quebra a UI
        print(f"Erro ao ler DynamoDB: {e}")
        return []

def archive_alert(id_recurso):
    """Arquiva o alerta"""
    try:
        dynamodb = get_db_resource()
        table = dynamodb.Table(TABLE_NAME)
        table.update_item(
            Key={'id_recurso': id_recurso},
            UpdateExpression="set estado_visualizacao = :s",
            ExpressionAttributeValues={':s': 'ARQUIVADO'}
        )
        st.toast(f"Alerta {id_recurso} arquivado!", icon="✅")
        time.sleep(0.5)
        st.rerun()
    except Exception as e:
        st.error(f"Erro ao arquivar (Provavelmente Offline): {e}")

# --- 5. LÓGICA PRINCIPAL (ORDEM IMPORTA!) ---

# 1º Passo: Checar Conexão (Rápido)
is_connected, status_msg = check_aws_connection()

# 2º Passo: Carregar dados SOMENTE se conectado
if is_connected:
    all_data = get_alerts(is_connected)
else:
    all_data = [] # Lista vazia para não quebrar a lógica abaixo

# Separação dos dados
alerts_novos = [x for x in all_data if x.get('estado_visualizacao') != 'ARQUIVADO']
alerts_historico = [x for x in all_data if x.get('estado_visualizacao') == 'ARQUIVADO']

# --- 6. INTERFACE GRÁFICA ---

# Sidebar
with st.sidebar:
    st.image("https://img.icons8.com/color/96/artificial-intelligence.png", width=80)
    st.title("Sentinel AI")
    st.markdown("---")
    
    menu_option = st.radio("Navegação", ["🚨 Monitoramento Ao Vivo", "📂 Histórico de Alertas"])
    
    st.markdown("---")
    # Hora local
    hora_atual = (datetime.utcnow() - timedelta(hours=3)).strftime('%H:%M:%S')
    st.caption(f"Última atualização: {hora_atual}")
    
    if st.button("🔄 Atualizar Agora"):
        st.rerun()

# --- TELA 1: MONITORAMENTO AO VIVO ---
if menu_option == "🚨 Monitoramento Ao Vivo":
    st.header("🚨 Centro de Comando")
    
    # Definição de Cores do Status
    cor_status = "normal" if is_connected else "inverse" # Vermelho se offline

    # Métricas
    col1, col2, col3 = st.columns(3)
    
    # Se estiver offline, mostramos "?" ou 0, mas avisamos no status
    qtd_ameacas = len(alerts_novos) if is_connected else "---"
    qtd_hist = len(alerts_historico) if is_connected else "---"
    
    col1.metric("Ameaças Ativas", qtd_ameacas, delta_color="inverse")
    col2.metric("Mitigadas / Histórico", qtd_hist)
    col3.metric("Status Conexão", status_msg, delta_color=cor_status)
    
    st.markdown("---")

    # MENSAGEM DE ERRO SE OFFLINE
    if not is_connected:
        st.error("🔌 CONEXÃO PERDIDA: O sistema não consegue contactar a nuvem AWS.")
        st.warning("⚠️ Os dados exibidos podem estar desatualizados. Tentando reconectar...")
    
    # CONTEÚDO (Só mostra se tiver dados ou se estiver seguro e online)
    elif not alerts_novos:
        st.success("✅ Ambiente Seguro. Nenhuma vulnerabilidade crítica detectada.")
        
    else:
        for item in alerts_novos:
            with st.container(border=True):
                c1, c2, c3 = st.columns([1, 5, 2])
                with c1: st.error("⚠️")
                with c2:
                    tipo = item.get('tipo', 'RECURSO').upper()
                    rid = item.get('id_recurso', 'N/A')
                    risco = item.get('risco', 'Pendente')
                    data_fmt = formatar_data_br(item.get('data_evento'))
                    
                    st.subheader(f"{tipo}: {rid}")
                    st.write(f"**Risco:** {risco}")
                    st.caption(f"📅 {data_fmt}")
                    
                    if 'json_analise' in item:
                        with st.expander("Ver Análise IA"):
                            try: st.json(json.loads(item['json_analise']) if isinstance(item['json_analise'], str) else item['json_analise'])
                            except: st.text(item['json_analise'])
                with c3:
                    st.write("")
                    st.write("")
                    if st.button("✅ Confirmar & Arquivar", key=f"btn_{item.get('id_recurso', 'x')}"):
                        archive_alert(item['id_recurso'])

# --- TELA 2: HISTÓRICO ---
elif menu_option == "📂 Histórico de Alertas":
    st.header("📂 Arquivo de Incidentes")
    
    if not is_connected:
        st.error("🔌 Sem conexão para carregar o histórico.")
    elif not alerts_historico:
        st.info("Nenhum histórico disponível.")
    else:
        for item in alerts_historico:
            data_fmt = formatar_data_br(item.get('data_evento'))
            rid = item.get('id_recurso', 'N/A')
            risco = item.get('risco', 'N/A')
            titulo = f"📅 {data_fmt} | {rid} | 🚩 {risco}"
            
            with st.expander(titulo):
                col_a, col_b = st.columns(2)
                with col_a:
                    st.markdown("### 📋 Detalhes")
                    st.write(f"**ID:** `{rid}`")
                    st.write(f"**Ação:** {item.get('auto_correcao', 'Monitoramento')}")
                    st.write(f"**Usuário:** `{item.get('usuario', 'System')}`")
                with col_b:
                    st.markdown("### 🧠 Análise IA")
                    try: st.json(json.loads(item['json_analise']) if isinstance(item['json_analise'], str) else item['json_analise'])
                    except: st.text(item.get('json_analise', '{}'))