import streamlit as st
import pandas as pd
import numpy as np
import logging
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score

# Logging Configuration

logging.basicConfig(
    filename="alerts.log",
    level=logging.WARNING,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

# Streamlit Config

st.set_page_config(
    page_title="AI-Based Network Intrusion Detection System",
    layout="wide"
)

# Global CSS (apply ONCE)

st.markdown(
    """
    <style>
        .block-container {
            padding-top: 1rem;
        }
        div.stButton > button {
            margin: 0 auto;
            display: block;
        }
    </style>
    """,
    unsafe_allow_html=True
)

# Feature Name Mapping

FEATURE_NAME_MAP = {
    "avg fwd segment size": "Average Forward Segment Size (bytes per segment)",
    "fwd packet length max": "Forward Packet Length – Maximum (bytes)",
    "fwd packet length mean": "Forward Packet Length – Mean (bytes)",
    "act data pkt fwd": "Active Data Packets in Forward Direction",
    "fwd iat std": "Forward Inter-Arrival Time – Std Deviation",
    "subflow fwd bytes": "Subflow Forward Bytes (total)",
    "fwd header length": "Forward Header Length (bytes)",
    "fwd header length.1": "Forward Header Length (duplicate feature)",
    "total fwd packets": "Total Forward Packets Count",
    "init win bytes forward": "Initial TCP Window Bytes – Forward",
    "fwd iat max": "Forward Inter-Arrival Time – Maximum"
}

# Load Dataset

@st.cache_data
@st.cache_data
def load_data():
    url = "https://huggingface.co/datasets/vidyadheesha-m-pandurangi/Cybersecurity-Datasets/resolve/main/Dataset.csv"
    return pd.read_csv(url, low_memory=False)

# Preprocessing

def preprocess_data(df):
    df = df.copy()
    df.columns = df.columns.str.strip().str.lower()

    label_col = next(
        (c for c in ["label", "class", "target", "attack"] if c in df.columns),
        None
    )
    if label_col is None:
        raise ValueError("No label column found")

    if df[label_col].dtype == object:
        df[label_col] = df[label_col].apply(
            lambda x: 0 if str(x).lower() in ["benign", "normal", "0"] else 1
        )

    df = df.select_dtypes(include=[np.number])
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(df.median(), inplace=True)
    df = df.astype(np.float32)

    X = df.drop(label_col, axis=1)
    y = df[label_col]

    return train_test_split(X, y, test_size=0.2, random_state=42)

# Train Model

@st.cache_resource
def train_model(X_train, y_train):
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=15,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train, y_train)
    return model

# Sidebar

st.sidebar.title("⚙️ Control Panel")
show_data = st.sidebar.checkbox("📊 Show Dataset")
train_button = st.sidebar.button("🚀 Train Model Now")

# Header

st.markdown(
    """
    <h1 style="text-align:center;">🔐 AI-Powered Network Intrusion Detection System</h1>
    <p style="text-align:center; font-size:18px;">
    Random Forest–based IDS with real-time alert logging and user-friendly traffic analysis
    </p>
    """,
    unsafe_allow_html=True
)

# Load Data

df = load_data()

if show_data:
    st.subheader("Dataset Preview")
    st.dataframe(df.head(50))

# Training Section

if train_button:
    with st.spinner("Training model..."):
        X_train, X_test, y_train, y_test = preprocess_data(df)
        model = train_model(X_train, y_train)

        acc = accuracy_score(y_test, model.predict(X_test))

        importance_df = pd.DataFrame({
            "Feature": X_train.columns,
            "Importance": model.feature_importances_
        }).sort_values(by="Importance", ascending=False)

        st.session_state["model"] = model
        st.session_state["all_features"] = X_train.columns.tolist()
        st.session_state["top_features"] = importance_df.head(10)["Feature"].tolist()
        st.session_state["model_trained"] = True

    st.success(f"✅ Model Trained Successfully | Accuracy: {acc:.2%}")

# Live Traffic Simulator 

if st.session_state.get("model_trained", False):

    st.markdown(
        "<h2 style='text-align:center;'>📡 Live Traffic Simulator</h2>",
        unsafe_allow_html=True
    )

    st.info(
        "Only the most influential network traffic parameters are shown below. "
        "These features contribute the most to intrusion detection decisions."
    )

    user_inputs = {}
    cols = st.columns(2)

    for i, feature in enumerate(st.session_state["top_features"]):
        label = FEATURE_NAME_MAP.get(feature, feature.replace("_", " ").title())
        with cols[i % 2]:
            user_inputs[feature] = st.number_input(
                label=label,
                value=0.0,
                help=label
            )
    with st.container():
        st.markdown("<br>", unsafe_allow_html=True)
        col_left, col_center, col_right = st.columns([1, 1, 1])

        with col_center:
            detect_clicked = st.button("🔍 Detect Traffic")

    if detect_clicked:
        full_input = {f: 0.0 for f in st.session_state["all_features"]}
        for f in user_inputs:
            full_input[f] = user_inputs[f]

        prediction = st.session_state["model"].predict(
            pd.DataFrame([full_input])
        )[0]

        if prediction == 1:
            st.error("🚨 Intrusion Detected!")
            logging.warning(f"INTRUSION DETECTED | Features: {user_inputs}")
        else:
            st.success("✅ Traffic is Benign")

else:
    st.warning("⚠️ Train the model to enable Live Traffic Analysis.")
