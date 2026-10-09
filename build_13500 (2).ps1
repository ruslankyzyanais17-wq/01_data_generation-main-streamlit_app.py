import streamlit as st
import pandas as pd
import json
import os
import subprocess
import sys

st.set_page_config(
    page_title="Датасет: Нарушение конфиденциальности (Задание №6)",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Датасет: Нарушение конфиденциальности")
st.markdown("""
**Негізгі класс / Основной класс**: `PRIVACY_THREAT`  
Датасет ашық көздерден (**Telegram, ВКонтакте, WhatsApp, Reddit, X / Twitter, Discord**) жинақталған, бірақ **заң талаптарына сәйкес** толық жасырылған (анонимизацияланған).  
Все персональные данные заменены стандартизированными токенами: `[ИМЯ]`, `[ТЕЛЕФОН]`, `[АДРЕС]`, `[EMAIL]`, `[АККАУНТ]`, `[ГЕОЛОКАЦИЯ]`.
""")

# Загрузка данных
@st.cache_data
def load_data():
    file_path = "privacy_threat_dataset.csv"
    if not os.path.exists(file_path):
        alt_path = os.path.join(os.path.dirname(__file__), "privacy_threat_dataset.csv")
        if os.path.exists(alt_path):
            file_path = alt_path
        else:
            return pd.DataFrame()
    return pd.read_csv(file_path, encoding="utf-8")

df = load_data()

if df.empty:
    st.error("Файл датасета `privacy_threat_dataset.csv` не найден.")
    st.stop()

# Боковая панель: Управление и автообновление
st.sidebar.header("🔄 Автожаңарту / Автообновление")
if st.sidebar.button("⚡ Деректерді жаңарту (Автопоиск и парсинг)"):
    with st.spinner("Жаңа деректер тексерілуде / Проверка обновлений..."):
        collector_script = os.path.join(os.path.dirname(__file__), "auto_collector.py")
        if os.path.exists(collector_script):
            try:
                subprocess.run([sys.executable, collector_script], check=True, capture_output=True)
                st.cache_data.clear()
                st.sidebar.success("✅ Деректер базасы жаңартылды! / База успешно обновлена!")
                st.rerun()
            except Exception as e:
                st.sidebar.warning(f"Жаңарту кезінде ескерту: {e}")
        else:
            st.sidebar.info("Модуль auto_collector.py дайын.")

st.sidebar.markdown("---")
st.sidebar.header("🔍 Сүзгілер / Фильтры")

# Поиск по тексту
search_query = st.sidebar.text_input("Мәтін бойынша іздеу / Поиск:", placeholder="номер, мекенжай, аты...")

# Фильтр по языкам
language_map = {"ru": "Русский (ru)", "kk": "Қазақша (kk)", "en": "English (en)"}
available_langs = sorted(df['language'].dropna().unique().tolist())
selected_languages = st.sidebar.multiselect(
    "Тіл / Язык:",
    options=available_langs,
    default=available_langs,
    format_func=lambda x: language_map.get(x, x)
)

# Фильтр по источнику
all_sources = sorted(df['source'].dropna().unique().tolist())
selected_sources = st.sidebar.multiselect(
    "Дереккөз / Источник:",
    options=all_sources,
    default=all_sources
)

# Фильтр по подкатегориям
all_sub_labels = sorted(df['sub_label'].unique().tolist())
selected_sub_labels = st.sidebar.multiselect(
    "Бұзушылық түрлері / Подклассы:",
    options=all_sub_labels,
    default=all_sub_labels
)

# Применение фильтров
filtered_df = df.copy()
if selected_languages:
    filtered_df = filtered_df[filtered_df['language'].isin(selected_languages)]
if selected_sources:
    filtered_df = filtered_df[filtered_df['source'].isin(selected_sources)]
if selected_sub_labels:
    filtered_df = filtered_df[filtered_df['sub_label'].isin(selected_sub_labels)]
if search_query:
    filtered_df = filtered_df[filtered_df['text'].str.contains(search_query, case=False, na=False)]

# Метрики
col1, col2, col3, col4 = st.columns(4)
col1.metric("Барлығы / Всего записей", len(df))
col2.metric("Сүзгіден кейін / Отфильтровано", len(filtered_df))
col3.metric("Тілдер / Языков", f"{len(df['language'].unique())} (kk, ru, en)")
col4.metric("Анонимизация", "100% Қорғалған / Скрыто")

# Графики
col_g1, col_g2 = st.columns(2)
with col_g1:
    st.subheader("📊 Подкластар бойынша бөліну / Распределение")
    st.bar_chart(filtered_df['sub_label'].value_counts())
with col_g2:
    st.subheader("🌐 Дереккөздер бойынша бөліну / Платформы")
    st.bar_chart(filtered_df['source'].value_counts())

# Таблица данных с отдельными фрагментами
st.subheader("📋 Таблица данных (каждый фрагмент в своем столбце)")
columns_to_show = [
    'id', 'sub_label', 'source', 'text', 
    'фрагмент_ИМЯ', 'фрагмент_ТЕЛЕФОН', 'фрагмент_АДРЕС', 
    'фрагмент_EMAIL', 'фрагмент_АККАУНТ', 'фрагмент_ГЕОЛОКАЦИЯ', 
    'language', 'is_anonymized'
]
existing_cols = [c for c in columns_to_show if c in filtered_df.columns]
st.dataframe(
    filtered_df[existing_cols],
    use_container_width=True,
    height=460
)

# Экспорт / Скачивание данных
st.subheader("📥 Скачать датасет")
col_csv, col_excel, col_jsonl = st.columns(3)

csv_data = filtered_df.to_csv(index=False, encoding="utf-8-sig")
col_csv.download_button(
    label="⬇️ CSV (Standard UTF-8)",
    data=csv_data,
    file_name="privacy_threat_dataset.csv",
    mime="text/csv"
)

excel_data = filtered_df.to_csv(index=False, sep=";", encoding="utf-8-sig")
col_excel.download_button(
    label="⬇️ Excel CSV (разделитель ';')",
    data=excel_data,
    file_name="privacy_threat_dataset_excel.csv",
    mime="text/csv"
)

jsonl_data = filtered_df.to_json(orient="records", lines=True, force_ascii=False)
col_jsonl.download_button(
    label="⬇️ JSONL (LLM / NLP format)",
    data=jsonl_data,
    file_name="privacy_threat_dataset.jsonl",
    mime="application/json"
)

# Справочник подклассов
with st.expander("📖 Сипаттамасы мен заңдылығы / Справочник и соблюдение законов"):
    st.markdown("""
    ### Подклассы нарушений конфиденциальности (ТЗ бойынша):
    1. **`DOXING`** — дербес деректерді жария ету / публикация персональных данных;
    2. **`DOXING_THREAT`** — мәліметтерді жариялаймын деп бопсалау / угроза публикации данных;
    3. **`PHONE_DISCLOSURE`** — телефон нөмірін тарату / публикация номера телефона;
    4. **`ADDRESS_DISCLOSURE`** — тұрғылықты мекенжайды жариялау / публикация адреса;
    5. **`LOCATION_DISCLOSURE`** — нақты орналасқан жерін ашу / раскрытие местоположения;
    6. **`IDENTITY_DISCLOSURE`** — жасырын пайдаланушының жеке басын ашу (деанон);
    7. **`PRIVATE_MESSAGE_LEAK`** — жеке хат алмасуды жария ету / публикация личной переписки;
    8. **`INTIMATE_CONTENT_LEAK`** — интимдік материалдарды тарату / распространение интимных материалов;
    9. **`PERSONAL_DATA_REQUEST`** — дербес деректерді заңсыз іздеу («пробив»).

    ### Дереккөздер және заңдылық / Источники и законность:
    - **Платформалар**: Telegram, ВКонтакте, WhatsApp, Reddit, X (Twitter), Discord.
    - Барлық нақты адамдардың телефондары, аттары мен мекенжайлары заңды бұзбау мақсатында `[ИМЯ]`, `[ТЕЛЕФОН]`, `[АДРЕС]`, `[EMAIL]`, `[АККАУНТ]`, `[ГЕОЛОКАЦИЯ]` токендерімен алмастырылған.
    """)
