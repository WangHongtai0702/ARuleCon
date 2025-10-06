import streamlit as st
from src.core import RuleGenerator


def page_rule_generation(model, title="RulePilot - Rule Generation"):
    """Rule Generation page"""
    if "rule_type" not in st.session_state:
        st.session_state.rule_type = "Splunk"

    st.title(title)

    # Use selectbox instead of buttons to select rule type
    rule_type = st.selectbox(
        "Select Rule Type:",
        ["Splunk", "Microsoft Sentinel", "Elastic"],
        key="rule_type_selector",
    )
    st.session_state.rule_type = rule_type

    rule_description = st.text_area(
        "Enter Rule Description:", placeholder="Describe the rule here..."
    )

    required_fields = st.text_area(
        "Enter Required Fields:", placeholder="List the required fields here..."
    )

    use_agent = st.checkbox(
        "Use Agent",
        help="Use AI Agent to generate and optimize the rule step by step",
    )

    if st.button("Generate Rule"):
        st.write("Generating rule...")
        st.session_state.use_agent = use_agent

        output_area = st.empty()
        progress_bar = st.progress(0)

        dsl_rules_output = ""
        steps_count = 16

        for idx, (step, result) in enumerate(
            RuleGenerator.web_rule_generator(
                rule_description,
                st.session_state.rule_type,
                required_fields,
                model=model,
            )
        ):
            if step == "FINAL_RULE":
                dsl_rules_output += f"\n\n### **Final Generated Rule:**\n{result}"
            elif step == "FINAL_RESULT":
                dsl_rules_output += f"\n\n### **Optimized DSL Rule:**\n{result}"
            else:
                dsl_rules_output += (
                    f"\n**{step.replace('_', ' ').title()}**:\n{result}\n"
                )

            output_area.markdown(dsl_rules_output)
            progress_bar.progress((idx + 1) / (steps_count + 2))
