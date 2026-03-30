import streamlit as st
import boto3
from datetime import datetime
import json
from dotenv import load_dotenv
from streamlit_autorefresh import st_autorefresh

load_dotenv()

# --- Configurações ---
st.set_page_config(page_title="Sentinel AI", page_icon="🛡️", layout="wide")

# Atualização Automática Assíncrona a cada 10 segundos
st_autorefresh(interval=10000, key="data_refresh")

# CSS
st.markdown("""
    <style>
    [data-testid="stMetricValue"] { font-size: 28px; }
    .stButton>button { border-radius: 5px; height: 2.5em; background-color: #262730; color: white; border: 1px solid #444; }
    .stButton>button:hover { border-color: #FFD700; color: #FFD700; }
    .date-text { font-size: 0.85em; color: #aaa; margin-bottom: 5px; }
    </style>
    """, unsafe_allow_html=True)

AWS_REGION = "us-east-2"
DYNAMODB_TABLE = "SentinelMonitor"

AWS_SERVICES = {
    "S3": "S3 (Armazenamento em Nuvem)",
    "EC2": "EC2 (Servidor Virtual)",
    "SG": "Security Group (Firewall)",
    "IAM": "IAM (Gestão de Identidade)",
    "IAC": "IaC (Código de Infraestrutura)"
}

# --- Barra Lateral ---
st.sidebar.title("🛡️ Sentinel AI")
st.sidebar.caption("Centro de Comando DevSecOps")
st.sidebar.markdown("---")

st.sidebar.markdown("### 🚦 Status do Sistema")
col_side1, col_side2 = st.sidebar.columns(2)
with col_side1:
    st.markdown("☁️ **Cloud**")
    st.markdown("🟢 **ONLINE**")
with col_side2:
    st.markdown("💻 **CI/CD**")
    st.markdown("🟢 **ONLINE**")

st.sidebar.markdown("---")

# --- Ingestão de Dadosr ---
@st.cache_resource
def get_dynamodb_resource():
    return boto3.resource('dynamodb', region_name=AWS_REGION)

def get_data():
    table = get_dynamodb_resource().Table(DYNAMODB_TABLE)
    try:
        response = table.scan()
        items = response.get('Items', [])
        items.sort(key=lambda x: x.get('data_evento', ''), reverse=True)
        return items
    except:
        return []

def update_status(item_id, novo_estado):
    table = get_dynamodb_resource().Table(DYNAMODB_TABLE)
    try:
        table.update_item(
            Key={'id_recurso': item_id},
            UpdateExpression="set estado_visualizacao = :s",
            ExpressionAttributeValues={':s': novo_estado}
        )
        return True
    except Exception as e:
        st.error(f"Erro ao atualizar banco: {e}")
        return False

def format_date_br(date_str):
    try:
        dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        return dt.strftime("%d/%m/%Y - %H:%M")
    except:
        return date_str

# --- Detalhes ---
@st.dialog("Relatório Detalhado")
def show_details(item, is_cloud=False):
    estado = item.get('estado_visualizacao')
    st.write(f"**Recurso:** `{item['id_recurso']}`")
    st.write(f"**Data:** {format_date_br(item.get('data_evento'))}")
    st.divider()
    
    st.markdown("#### 🧠 Análise do Sentinel AI")
    if estado == 'CONFIRMADO':
        st.warning("⚠️ Incidente revisado e remediação confirmada.")
    else:
        st.error(item.get('risco', 'Risco identificado.'))
    
    st.divider()
    st.markdown("#### 🛠️ Resposta e Ações")
    st.info(f"**Ação Automática:** {item.get('auto_correcao', 'Monitoramento ativo.')}")
    
    if is_cloud and estado != 'CONFIRMADO':
        st.write("")
        if st.button("✅ Confirmar Remediação"):
            if update_status(item['id_recurso'], 'CONFIRMADO'):
                st.success("Remediação Confirmada! Limpando fila...")
                st.rerun()

    with st.expander("Ver Log JSON"):
        st.json(item.get('json_analise', '{}'))

# --- Interface ---
menu = st.sidebar.radio("Navegação", ["🚨 Monitoramento Cloud", "💻 Pipeline CI/CD", "📂 Histórico Geral"])
if st.sidebar.button("🔄 Atualizar Dashboard"):
    st.rerun()

all_data = get_data()

def render_cards(data_list, limit=None, is_cloud=False):
    if not data_list:
        st.info("Nenhum registro pendente.")
        return
    display_data = data_list[:limit] if limit else data_list
    for item in display_data:
        tipo = item.get('tipo', 'SCAN').upper()
        servico = AWS_SERVICES.get(tipo, tipo)
        estado = item.get('estado_visualizacao')
        
        if estado == 'CONFIRMADO':
            border_color = "#FFD700" 
            bg_tag = "#443a00"
            status_txt = "⚠️ CONFIRMADO"
        elif item.get('status_ia') == 'VULNERAVEL' or item.get('gravidade') == 'ALTA':
            border_color = "#ff4b4b"
            bg_tag = "#632020"
            status_txt = "🚫 ALERTA"
        else:
            border_color = "#28a745"
            bg_tag = "#1b3a1e"
            status_txt = "✅ SEGURO"

        with st.container():
            st.markdown(f"""
                <div style="border-left: 6px solid {border_color}; background-color: #262730; padding: 15px; border-radius: 8px; margin-bottom: 10px;">
                    <div class="date-text">{format_date_br(item.get('data_evento'))}</div>
                    <div style="margin-bottom: 8px;">
                        <span style="background-color: {bg_tag}; padding: 2px 8px; border-radius: 4px; font-size: 0.7em; font-weight: bold;">{status_txt}</span>
                        <strong style="margin-left: 5px;">{servico}</strong>
                    </div>
                    <div style="font-size: 0.9em; color: #ddd; margin-bottom: 10px;">
                        ID: <code>{item.get('id_recurso')}</code>
                    </div>
                </div>
            """, unsafe_allow_html=True)
            if st.button(f"🔍 Ver Detalhes", key=f"btn_{item['id_recurso']}_{item.get('data_evento', '')}"):
                show_details(item, is_cloud=is_cloud)
            st.markdown("<br>", unsafe_allow_html=True)

# --- Abas ---
if menu == "🚨 Monitoramento Cloud":
    st.header("🚨 Monitoramento Cloud (Pendentes)")
    
    # FILTRO: Apenas o que NÃO foi confirmado e NÃO é IAC
    active_cloud = [x for x in all_data if x.get('tipo') != 'IAC' and x.get('estado_visualizacao') != 'CONFIRMADO']
    
    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Ameaças Ativas", len(active_cloud))
    k2.metric("Críticos 🔥", len([x for x in active_cloud if x.get('gravidade') == 'ALTA']))
    k3.metric("Auto-Remediados (IA) 🤖", len([x for x in all_data if x.get('auto_correcao') and 'remediado' in str(x.get('auto_correcao')).lower()]))
    k4.metric("Validações Humanas ✅", len([x for x in all_data if x.get('estado_visualizacao') == 'CONFIRMADO']))
    
    st.markdown("---")
    render_cards(active_cloud, limit=5, is_cloud=True)

elif menu == "💻 Pipeline CI/CD":
    st.header("💻 Pipeline CI/CD (Atividade Recente)")
    pipe = [x for x in all_data if x.get('tipo') == 'IAC']
    total = len(pipe)
    reprovados = len([x for x in pipe if x.get('status_ia') == 'VULNERAVEL'])
    c1, c2, c3 = st.columns(3)
    c1.metric("Commits Analisados", total)
    c2.metric("Aprovados ✅", total - reprovados)
    c3.metric("Bloqueados 🚫", reprovados, delta=reprovados * -1, delta_color="inverse")
    st.markdown("---")
    render_cards(pipe, limit=5)

elif menu == "📂 Histórico Geral":
    st.header("📂 Histórico Geral de Segurança")
    st.columns(1)[0].metric("Total de Eventos Processados", len(all_data))
    st.markdown("---")
    render_cards(all_data)