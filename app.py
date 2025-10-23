import streamlit as st
import os
from src.pages.rule_conversion import page_rule_conversion
from src.llms.client import refresh_client


def main_page():
    # Sidebar configuration
    api_key_openai = st.sidebar.text_input(
        "OpenAI API Key",
        st.session_state.get("OPENAI_API_KEY", ""),
        type="password",
    )
    model_openai = st.sidebar.selectbox(
        "OpenAI Model",
        ("gpt-5-mini", "gpt-5", "gpt-4o-mini", "gpt-4o", "gpt-3.5-turbo"),
    )

    # Only show Rule Conversion
    page = "Rule Conversion"

    settings = {
        "model": model_openai,
        "model_provider": "openai",
    }
    st.session_state["OPENAI_API_KEY"] = api_key_openai
    os.environ["OPENAI_API_KEY"] = st.session_state["OPENAI_API_KEY"]
    os.environ["MODEL_NAME"] = settings["model"]
    # Load existing .env first
    from dotenv import load_dotenv

    load_dotenv(override=False)

    # Initialize session state from .env
    st.session_state["OPENAI_API_KEY"] = os.getenv("OPENAI_API_KEY", "")
    st.session_state["DEFAULT_MODEL"] = os.getenv("MODEL_NAME", "gpt-4o")

    # Initialize current API key if not set
    if "CURRENT_API_KEY" not in st.session_state:
        st.session_state["CURRENT_API_KEY"] = st.session_state["OPENAI_API_KEY"]

    # Sync UI changes to .env
    if api_key_openai or model_openai != st.session_state["DEFAULT_MODEL"]:
        with open(".env", "w", encoding="utf-8") as f:
            f.write(f"OPENAI_API_KEY={api_key_openai}\n")
            f.write(f"MODEL_NAME={model_openai}\n")
        # 只有在API Key真正发生变化时才重新初始化client
        if api_key_openai and api_key_openai != st.session_state.get(
            "CURRENT_API_KEY", ""
        ):
            refresh_client()
            st.session_state["CURRENT_API_KEY"] = api_key_openai

    # Display Rule Conversion page
    page_rule_conversion(model_openai)


if __name__ == "__main__":
    main_page()
