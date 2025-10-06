import streamlit as st
import json
from src.core import generate_ir, analyze_rule


def page_rule_ir_generation(model, title="RulePilot - Rule IR Generation"):
    """Rule IR Generation page - Show the process of generating IR for different rule types"""
    st.title(title)
    st.write(
        "Generate Intermediate Representation (IR) for different types of security rules."
    )

    # Rule type selection
    rule_type = st.selectbox(
        "Select Rule Type:",
        [
            "Splunk",
            "Microsoft Sentinel",
            "IBM QRadar AQL",
            "Google Chronicle YARA-L",
            "RSA NetWitness ESA",
        ],
        key="ir_rule_type_selector",
    )

    # Input rule content
    rule_content = st.text_area(
        "Enter Rule Content:",
        placeholder=f"Paste your {rule_type} rule content here...",
        height=200,
        key="ir_rule_content",
    )

    # Options for IR generation
    col1, col2 = st.columns(2)

    with col1:
        use_analysis = st.checkbox(
            "Use Rule Analysis",
            value=True,
            help="First analyze the rule, then generate IR based on the analysis",
        )

    with col2:
        show_steps = st.checkbox(
            "Show Generation Steps",
            value=True,
            help="Display the step-by-step process of IR generation",
        )

    if st.button("Generate IR", type="primary"):
        if rule_content:
            try:
                with st.spinner("🔄 Generating IR... Please wait."):

                    # Step 1: Rule Analysis (if enabled)
                    if use_analysis:
                        st.subheader("📋 Step 1: Rule Analysis")
                        with st.expander("View Rule Analysis", expanded=True):
                            rule_analysis = analyze_rule(rule_content, model)
                            st.markdown(rule_analysis)
                    else:
                        rule_analysis = None
                        st.subheader("📋 Step 1: Rule Analysis")
                        st.info("Rule analysis skipped.")

                    # Step 2: IR Generation
                    st.subheader("🔧 Step 2: IR Generation")
                    with st.expander("View IR Generation Process", expanded=True):
                        if show_steps:
                            st.write("**Input to IR Generator:**")
                            st.json(
                                {
                                    "rule_content": rule_content,
                                    "rule_type": rule_type,
                                    "use_analysis": use_analysis,
                                    "has_analysis": rule_analysis is not None,
                                }
                            )

                            st.write("**Generating IR...**")
                            progress_bar = st.progress(0)

                            # Simulate progress
                            for i in range(3):
                                progress_bar.progress((i + 1) / 3)
                                # st.write(f"Processing step {i + 1}...")
                                st.empty()

                        # Generate IR
                        ir_result = generate_ir(
                            rule_content,
                            model,
                            rule_type=rule_type,
                            rule_analysis=rule_analysis,
                        )

                    # Step 3: Display Results
                    st.subheader("✅ Step 3: Generated IR")

                    # Display IR in a nice format
                    col1, col2 = st.columns([2, 1])

                    with col1:
                        st.json(ir_result)

                    with col2:
                        st.write("**IR Summary:**")
                        st.write(f"**Rule Name:** {ir_result.get('rule_name', 'N/A')}")
                        st.write(
                            f"**Data Source:** {ir_result.get('data_source', 'N/A')}"
                        )
                        st.write(
                            f"**Event Type:** {ir_result.get('event_type', 'N/A')}"
                        )
                        st.write(f"**Steps Count:** {len(ir_result.get('steps', []))}")

                        if ir_result.get("description"):
                            st.write("**Description:**")
                            st.info(ir_result["description"])

                    # Step 4: IR Validation
                    st.subheader("🔍 Step 4: IR Validation")
                    with st.expander("IR Structure Validation", expanded=False):
                        validation_results = validate_ir_structure(ir_result)
                        for field, status in validation_results.items():
                            if status:
                                st.success(f"✅ {field}: Valid")
                            else:
                                st.error(f"❌ {field}: Invalid")

                    # Download option
                    st.subheader("💾 Download IR")
                    ir_json = json.dumps(ir_result, indent=2)
                    st.download_button(
                        label="Download IR as JSON",
                        data=ir_json,
                        file_name=f"{ir_result.get('rule_name', 'rule')}_ir.json",
                        mime="application/json",
                    )

            except Exception as e:
                st.error(f"❌ IR Generation failed: {str(e)}")
                st.exception(e)
        else:
            st.warning("⚠️ Please enter rule content to generate IR.")


def validate_ir_structure(ir_result):
    """Validate the structure of generated IR"""
    validation = {}

    # Check required fields
    required_fields = ["rule_name", "description", "data_source", "event_type", "steps"]
    for field in required_fields:
        validation[field] = field in ir_result and ir_result[field]

    # Check steps structure
    if "steps" in ir_result and isinstance(ir_result["steps"], list):
        validation["steps_structure"] = True
        for i, step in enumerate(ir_result["steps"]):
            if isinstance(step, dict):
                step_fields = ["action", "params", "explanation"]
                for step_field in step_fields:
                    validation[f"step_{i}_{step_field}"] = (
                        step_field in step and step[step_field]
                    )
            else:
                validation[f"step_{i}_type"] = False
    else:
        validation["steps_structure"] = False

    return validation
