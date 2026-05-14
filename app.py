import streamlit as st
import joblib
import numpy as np
import pandas as pd
from datetime import datetime

# 1. Sayfa Konfigürasyonu ve Hafıza Başlatma
st.set_page_config(page_title="IDS Network Pro", page_icon="🌐", layout="wide")

if 'gecmis' not in st.session_state:
    st.session_state.gecmis = []

# 2. Modeli Yükle
@st.cache_resource
def load_model():
    return joblib.load('ids_random_forest_model.pkl')

model = load_model()

# 41 Parametre Listesi
feature_names = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land',
    'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised',
    'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
    'num_access_files', 'num_outbound_cmds', 'is_host_login', 'is_guest_login',
    'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
    'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
    'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
    'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
]

# 3. Senaryo Veri Havuzu (Gerçek NSL-KDD Verileri)
senaryo_paketleri = {
    "Manuel Mod": None,
    "Normal Trafik (Web Gezintisi)": [0, 1, 22, 9, 215, 45076, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0, 0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
    "Neptune Saldırısı (DoS)": [0, 1, 49, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 229, 10, 1.0, 1.0, 0.0, 0.0, 0.04, 0.06, 0.0, 255, 10, 0.04, 0.06, 0.0, 0.0, 1.0, 1.0, 0.0, 0.0],
    "Nmap Tarama (Port Scan)": [0, 1, 37, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 255, 1, 0.0, 1.0, 1.0, 0.0, 1.0, 1.0, 0.0, 0.0]
}

# 4. Arayüz Tasarımı
st.title("🛡️ Akıllı Ağ Saldırı Tespit Sistemi Laboratuvarı")

col1, col2 = st.columns([1, 2])

with col1:
    st.header("🎯 Girdi Kontrolü")
    secilen_senaryo = st.selectbox("Bir Analiz Senaryosu Seçin:", list(senaryo_paketleri.keys()))
    
    st.markdown("---")
    st.subheader("📡 Parametre Düzenleme")
    
    # Eğer senaryo seçiliyse değerleri oradan al, değilse varsayılan kalsın
    base_data = senaryo_paketleri[secilen_senaryo] if senaryo_paketleri[secilen_senaryo] else [0]*41
    
    with st.expander("Temel Ayarlar", expanded=True):
        m_duration = st.number_input("Süre", value=int(base_data[0]))
        m_src = st.number_input("Src Bytes", value=int(base_data[4]))
        m_dst = st.number_input("Dst Bytes", value=int(base_data[5]))
    
    with st.expander("Gelişmiş Network Ayarları"):
        m_serror = st.slider("Serror Rate (Hata)", 0.0, 1.0, float(base_data[24]))
        m_count = st.number_input("Aynı Hedefe Bağlantı (Count)", value=int(base_data[22]))
        m_protocol = st.selectbox("Protokol", [1, 2, 0], index=1 if base_data[1] == 1 else 0)

    # 41'lik diziyi oluştur
    final_input = np.array(base_data)
    if secilen_senaryo == "Manuel Mod":
        final_input[0] = m_duration
        final_input[4] = m_src
        final_input[5] = m_dst
        final_input[24] = m_serror
        final_input[22] = m_count
        final_input[1] = m_protocol

    st.button("🚀 ANALİZİ BAŞLAT", on_click=lambda: st.session_state.update({"run": True}), use_container_width=True)

with col2:
    st.header("🔍 Analiz ve Şeffaflık")
    
    # Modele giden ham veriyi göster (Şeffaflık için)
    display_df = pd.DataFrame({"Parametre": feature_names, "Değer": final_input})
    st.subheader("Modele Giden Paket İmzası")
    st.dataframe(display_df[display_df["Değer"] != 0], height=250, use_container_width=True)

    if st.session_state.get("run"):
        prediction = model.predict(final_input.reshape(1, -1))
        probs = model.predict_proba(final_input.reshape(1, -1))
        
        res_id = int(prediction[0])
        conf = np.max(probs) * 100
        
        st.markdown("---")
        if res_id == 11:
            st.success(f"**TEŞHİS: NORMAL (GÜVENLİ)**")
        else:
            st.error(f"**TEŞHİS: SALDIRI TESPİT EDİLDİ (Sınıf: {res_id})**")
            
        st.metric("Model Güven Skoru", f"%{conf:.2f}")
        st.progress(conf / 100)
        
        # Log kaydı
        st.session_state.gecmis.append({
            "Saat": datetime.now().strftime("%H:%M:%S"),
            "Sonuç": "Normal" if res_id == 11 else f"Saldırı ({res_id})",
            "Güven": f"%{conf:.2f}",
            "Senaryo": secilen_senaryo
        })
        st.session_state["run"] = False

# 5. Loglar
st.markdown("---")
st.header("📋 Olay Kayıtları")
if st.session_state.gecmis:
    st.table(pd.DataFrame(st.session_state.gecmis).iloc[::-1])