
# Akıllı Ağ Saldırı Tespit Sistemi (NIDS) 🛡️

Bu proje, makine öğrenmesi tekniklerini kullanarak ağ trafiği verilerini analiz eden ve olası siber saldırıları gerçek zamanlı olarak tespit eden bir **Ağ Saldırı Tespit Sistemi (NIDS)** uygulamasıdır. 

Uygulama, **NSL-KDD** veri kümesi üzerinde eğitilmiş bir **Random Forest** modeli kullanır ve **Streamlit** üzerinden modern bir web arayüzü sunar.

## ✨ Özellikler
- **Yüksek Doğruluk:** Random Forest algoritması ile ağ paketleri üzerinde hassas sınıflandırma.
- **Detaylı Teşhis:** Saldırıları; DoS, Probe, R2L ve U2R gibi alt kategoriler bazında teşhis edebilir.
- **Şeffaf Analiz:** Modele giden ham verilerin ve modelin güven (confidence) skorunun anlık takibi.
- **Kullanıcı Dostu Arayüz:** Teknik detaylara boğulmadan ağ paket analizi yapma imkanı.

## 📂 Proje Yapısı
- `app.py`: Streamlit Web arayüzü ve tahminleme mantığı.
- `ids_uygulama.ipynb`: Modelin eğitim, veri temizleme ve analiz sürecini içeren Jupyter Notebook.
- `ids_random_forest_model.pkl`: Eğitilmiş ana makine öğrenmesi modeli.
- `label_encoder.pkl`: Kategorik verileri (protokol, servis vb.) sayısal verilere dönüştüren encoder.
- `KDDTrain+_20Percent.txt`: Modelin eğitildiği NSL-KDD veri seti örneği.
- `requirements.txt`: Projenin çalışması için gerekli Python kütüphaneleri.

## 🛠️ Kurulum ve Çalıştırma

Projeyi yerel bilgisayarınızda çalıştırmak için:

1. **Gerekli kütüphaneleri yükleyin:**
   ```bash
   pip install -r requirements.txt
   
2. **Uygulamayı başlatın:**
   streamlit run app.py

2. **Kullanılan Teknolojiler:**
    Python 3.11+

    Scikit-learn: Makine öğrenmesi modeli için.

    Pandas & Numpy: Veri işleme.

    Streamlit: Dashboard ve kullanıcı arayüzü.

    Joblib: Modelin kaydedilmesi ve yüklenmesi.
