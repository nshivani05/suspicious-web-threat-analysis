import streamlit as st
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import pycountry
import altair as alt

st.set_page_config(page_title="🛡️ Web Threat Analyzer", layout="wide")

# Load data
@st.cache_data
def load_data():
    df = pd.read_csv(r"C:\Users\hp\Desktop\Mini_project_files\UM\Cybersecurity Suspicious Web Threat Interactions\CloudWatch_Traffic_Web_Attack.csv")
    df['time'] = pd.to_datetime(df['time'])
    df['date'] = df['time'].dt.date
    df['hour'] = df['time'].dt.hour
    df['day_of_week'] = df['time'].dt.day_name()
    return df

df = load_data()

# Country name mapping
def get_country_name(code):
    try:
        return pycountry.countries.get(alpha_2=code).name
    except:
        return code

df['country_full'] = df['src_ip_country_code'].apply(get_country_name)

# Sidebar Filters
with st.sidebar:
    st.title("🔍 Filters")
    st.markdown("Use these filters to narrow your analysis.")

    selected_country = st.multiselect(
        "🌍 Source Country",
        options=sorted(df['country_full'].dropna().unique()),
        default=sorted(df['country_full'].dropna().unique())
    )

    selected_protocol = st.multiselect(
        "📡 Protocol",
        options=sorted(df['protocol'].dropna().unique()),
        default=sorted(df['protocol'].dropna().unique())
    )

# Apply filters
filtered_df = df[
    (df['country_full'].isin(selected_country)) &
    (df['protocol'].isin(selected_protocol))
]

# Main Title
st.title("🕵️ Suspicious Web Threat Dashboard")
st.caption("Explore AWS CloudWatch attack patterns and traffic anomalies.")

# Tabs for layout
tab1, tab2, tab3 = st.tabs(["📊 Overview", "🔴 Anomalies", "🌍 Country Map"])

# --- 📊 Overview Tab ---
with tab1:
    st.subheader("📈 Summary Insights")
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Records", len(filtered_df))
    col2.metric("Unique IPs", filtered_df['src_ip'].nunique())
    col3.metric("Date Range", f"{filtered_df['date'].min()} → {filtered_df['date'].max()}")

    st.markdown("### ⏱️ Suspicious Interactions Over Time")
    daily = filtered_df.groupby("date").size()
    st.line_chart(daily)

    st.markdown("### 📊 Suspicious Requests by Country")
    top_countries = filtered_df['country_full'].value_counts().head(15)
    fig1, ax1 = plt.subplots(figsize=(10, 5))
    sns.barplot(y=top_countries.index, x=top_countries.values, palette="viridis", ax=ax1)
    ax1.set_xlabel("Number of Requests")
    ax1.set_ylabel("Country")
    ax1.set_title("Top 15 Countries by Suspicious Requests")
    st.pyplot(fig1)

# --- 🔴 Anomaly Detection Tab ---
with tab2:
    st.subheader("🔍 Traffic Anomaly Detection")
    threshold = df['bytes_out'].quantile(0.95)
    filtered_df['is_anomaly'] = filtered_df['bytes_out'] > threshold

    fig2, ax2 = plt.subplots(figsize=(10, 5))
    sns.scatterplot(data=filtered_df, x='time', y='bytes_out', hue='is_anomaly', palette={True: 'red', False: 'blue'}, ax=ax2)
    ax2.set_title("📉 Anomalous Traffic Volume")
    st.pyplot(fig2)

    with st.expander("📋 View Anomalous Records"):
        st.dataframe(filtered_df[filtered_df['is_anomaly'] == True][[
            'time', 'src_ip', 'country_full', 'protocol', 'bytes_out'
        ]])

# --- 🌍 Country Map Tab ---
with tab3:
    st.subheader("🌍 Geographic Distribution")
    country_counts = df['country_full'].value_counts().reset_index()
    country_counts.columns = ['country', 'count']

    # Map using Altair
    chart = alt.Chart(country_counts).mark_bar().encode(
        y=alt.Y("country:N", sort='-x'),
        x="count:Q",
        tooltip=["country", "count"]
    ).properties(height=500, title="Suspicious Traffic by Country")

    st.altair_chart(chart, use_container_width=True)

# Footer
st.markdown("---")
st.caption("Made using Streamlit")
