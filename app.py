import streamlit as st
import os
from src.pages.rule_generation import page_rule_generation
from src.pages.rule_conversion import page_rule_conversion
from src.pages.rule_ir_generation import page_rule_ir_generation
from src.pages.semantic_optimization_test import page_semantic_optimization_test
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
        ("gpt-4o-mini", "gpt-4o", "gpt-3.5-turbo"),
    )

    # Add sidebar page switching
    page = st.sidebar.selectbox(
        "Select Function",
        [
            "Rule Generation",
            "Rule Conversion",
            "Rule IR Generation",
            "Semantic Optimization Test",
        ],
        key="page_selector",
    )

    settings = {
        "model": model_openai,
        "model_provider": "openai",
        "temperature": 0.3,
    }
    st.session_state["OPENAI_API_KEY"] = api_key_openai
    os.environ["OPENAI_API_KEY"] = st.session_state["OPENAI_API_KEY"]
    os.environ["MODEL_NAME"] = settings["model"]
    # Load existing .env first
    from dotenv import load_dotenv

    load_dotenv(override=False)

    # Initialize session state from .env
    st.session_state["OPENAI_API_KEY"] = os.getenv("OPENAI_API_KEY", "")
    st.session_state["DEFAULT_MODEL"] = os.getenv("MODEL_NAME", "gpt-4-turbo")

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

    # Display different functions based on selected page
    if page == "Rule Conversion":
        page_rule_conversion(model_openai)
    elif page == "Rule Generation":
        page_rule_generation(model_openai)
    elif page == "Rule IR Generation":
        page_rule_ir_generation(model_openai)
    elif page == "Semantic Optimization Test":
        page_semantic_optimization_test(model_openai)


if __name__ == "__main__":
    main_page()
