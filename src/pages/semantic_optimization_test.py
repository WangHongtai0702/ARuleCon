"""
Semantic Optimization Test Page
For testing and demonstrating semantic optimization processes
"""

import streamlit as st
import json
import time
from typing import Dict, Any, List
from src.core.rule_optimizer import SemanticRuleOptimizer
from src.core.rule_converter import generate_ir
from src.llms.client import get_client, refresh_client


def page_semantic_optimization_test(
    model=None, title="RulePilot - Semantic Optimization Test"
):
    """Semantic optimization test page"""
    st.title(title)
    st.markdown("---")

    # Page description
    st.markdown(
        """
    ### Feature Description
    This page is used for testing and demonstrating semantic optimization processes. You can:
    1. Input source rule and target rule
    2. View the complete optimization process, including IR generation, code block generation, output comparison, etc.
    3. View the optimized target rule
    """
    )

    # Configuration area
    with st.expander("⚙️ Configuration Settings", expanded=True):
        col1, col2 = st.columns(2)

        with col1:
            source_rule_type = st.selectbox(
                "Source Rule Type",
                [
                    "Splunk",
                    "Microsoft Sentinel",
                    "IBM QRadar",
                    "Google Chronicle",
                    "RSA NetWitness",
                ],
                key="source_rule_type",
            )

        with col2:
            target_rule_type = st.selectbox(
                "Target Rule Type",
                [
                    "Splunk",
                    "Microsoft Sentinel",
                    "IBM QRadar",
                    "Google Chronicle",
                    "RSA NetWitness",
                ],
                key="target_rule_type",
            )

    # Rule input area
    st.markdown("### 📝 Rule Input")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### Source Rule")
        source_rule = st.text_area(
            "Enter source rule content",
            height=200,
            placeholder="e.g., index=security sourcetype=firewall | search action=block",
            key="source_rule_input",
        )

    with col2:
        st.markdown("#### Target Rule")
        target_rule = st.text_area(
            "Enter target rule content",
            height=200,
            placeholder="e.g., SecurityEvent | where EventID == 5156 | where Action == 'block'",
            key="target_rule_input",
        )

    # Example rules
    with st.expander("📋 Example Rules", expanded=False):
        st.markdown(
            """
        **Splunk Example:**
        ```
        index=security sourcetype=firewall | search action=block | stats count by src_ip
        ```

        **Microsoft Sentinel Example:**
        ```
        SecurityEvent | where EventID == 5156 | where Action == 'block' | summarize count() by Computer
        ```
        """
        )

    # Start optimization button
    if st.button(
        "🚀 Start Semantic Optimization", type="primary", use_container_width=True
    ):
        if not source_rule.strip() or not target_rule.strip():
            st.error("Please enter both source rule and target rule content")
            return

        if source_rule_type == target_rule_type:
            st.warning(
                "Source rule type and target rule type are the same. It's recommended to use different rule types for testing"
            )

        # Start optimization process
        run_semantic_optimization(
            source_rule, target_rule, source_rule_type, target_rule_type, model
        )


def run_semantic_optimization(
    source_rule: str,
    target_rule: str,
    source_rule_type: str,
    target_rule_type: str,
    model=None,
):
    """Run semantic optimization process"""

    # Create progress bar
    progress_bar = st.progress(0)
    status_text = st.empty()

    try:
        # Initialize client
        if model:
            client = model
        else:
            client = get_client()
            if not client:
                st.error(
                    "Unable to initialize LLM client, please check API configuration"
                )
                return

        # Step 1: Generate source rule IR
        status_text.text("🔍 Step 1: Generating source rule IR...")
        progress_bar.progress(0.1)

        # Ensure client is available for generate_ir
        if model:
            refresh_client()

        source_ir = generate_ir(
            source_rule, model if model else "gpt-4o-mini", source_rule_type
        )
        if not source_ir or source_ir.get("rule_name") == "error_rule":
            st.error(
                f"❌ Source rule IR generation failed: {source_ir.get('description', 'Unknown error')}"
            )
            return

        st.success("✅ Source rule IR generated successfully")

        # Display source rule IR
        with st.expander("📋 Source Rule IR Details", expanded=False):
            st.json(source_ir)

        # Step 2: Generate target rule IR
        status_text.text("🔍 Step 2: Generating target rule IR...")
        progress_bar.progress(0.2)

        target_ir = generate_ir(
            target_rule, model if model else "gpt-4o-mini", target_rule_type
        )
        if not target_ir or target_ir.get("rule_name") == "error_rule":
            st.error(
                f"❌ Target rule IR generation failed: {target_ir.get('description', 'Unknown error')}"
            )
            return

        st.success("✅ Target rule IR generated successfully")

        # Display target rule IR
        with st.expander("📋 Target Rule IR Details", expanded=False):
            st.json(target_ir)

        # Step 3: Execute semantic optimization
        status_text.text("🧠 Step 3: Executing semantic optimization...")
        progress_bar.progress(0.3)

        # Initialize semantic optimizer
        semantic_optimizer = SemanticRuleOptimizer(model=client)

        # Execute semantic optimization
        optimization_result = semantic_optimizer.optimize_rule_semantics(
            original_rule=source_rule,
            converted_rule=target_rule,
            original_ir=source_ir,
            converted_ir=target_ir,
            source_rule_type=source_rule_type,
            target_rule_type=target_rule_type,
        )

        if not optimization_result["success"]:
            st.error(
                f"❌ Semantic optimization failed: {optimization_result.get('error', 'Unknown error')}"
            )
            return

        progress_bar.progress(0.8)
        status_text.text("✅ Semantic optimization completed")

        # Display optimization results
        display_optimization_results(optimization_result, source_rule, target_rule)

        progress_bar.progress(1.0)
        status_text.text("🎉 All steps completed!")

    except Exception as e:
        st.error(f"❌ Optimization process error: {str(e)}")
        import traceback

        st.code(traceback.format_exc())


def display_optimization_results(
    result: Dict[str, Any], source_rule: str, target_rule: str
):
    """Display optimization results"""

    st.markdown("---")
    st.markdown("## 📊 Optimization Results")

    # Overall metrics
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            "Semantic Equivalence Score",
            f"{result['semantic_equivalence_score']:.2f}",
            help="Score between 0-1, where 1 indicates complete equivalence",
        )

    with col2:
        comparison = result["comparison_results"]
        st.metric(
            "Test Matches",
            f"{comparison['matches']}/{comparison['total_tests']}",
            help="Number of matching test cases",
        )

    with col3:
        st.metric(
            "Code Blocks Count",
            f"{len(result['original_code_blocks'])}",
            help="Number of generated code blocks",
        )

    with col4:
        st.metric(
            "Test Data Count",
            f"{len(result['test_log_data'])}",
            help="Number of generated test data entries",
        )

    # Detailed results tabs
    tab1, tab2, tab3, tab4, tab5 = st.tabs(
        [
            "📋 Test Results",
            "🔧 Code Blocks",
            "📊 Execution Context",
            "💡 Optimization Suggestions",
            "🎯 Optimized Rule",
        ]
    )

    with tab1:
        display_test_results(result)

    with tab2:
        display_code_blocks(result)

    with tab3:
        display_execution_context(result)

    with tab4:
        display_optimization_suggestions(result)

    with tab5:
        display_optimized_rule(result, source_rule, target_rule)


def display_test_results(result: Dict[str, Any]):
    """Display test results"""
    st.markdown("### 🧪 Test Execution Results")

    comparison = result["comparison_results"]

    # Test statistics
    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### 📈 Test Statistics")
        st.write(f"- **Total Tests**: {comparison['total_tests']}")
        st.write(f"- **Matches**: {comparison['matches']}")
        st.write(f"- **Mismatches**: {comparison['mismatches']}")
        st.write(
            f"- **Match Rate**: {comparison['matches']/comparison['total_tests']*100:.1f}%"
        )

    with col2:
        st.markdown("#### 📊 Result Distribution")
        if comparison["total_tests"] > 0:
            import matplotlib.pyplot as plt
            import numpy as np

            fig, ax = plt.subplots(figsize=(6, 4))
            labels = ["Matches", "Mismatches"]
            sizes = [comparison["matches"], comparison["mismatches"]]
            colors = ["#2E8B57", "#DC143C"]

            ax.pie(
                sizes, labels=labels, colors=colors, autopct="%1.1f%%", startangle=90
            )
            ax.set_title("Test Result Distribution")
            st.pyplot(fig)

    # Detailed test data
    if result["test_log_data"]:
        st.markdown("#### 📝 Test Data Samples")
        with st.expander("View Test Data", expanded=False):
            for i, log_entry in enumerate(result["test_log_data"][:3], 1):
                try:
                    log_data = json.loads(log_entry)
                    st.write(f"**Test {i}:**")
                    st.json(log_data)
                except:
                    st.write(f"**Test {i}:**")
                    st.text(log_entry)


def display_code_blocks(result: Dict[str, Any]):
    """Display code blocks"""
    st.markdown("### 🔧 Generated Code Blocks")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### Source Rule Code Blocks")
        for i, code_block in enumerate(result["original_code_blocks"], 1):
            st.write(f"**Code Block {i}:**")
            st.code(code_block, language="python")

    with col2:
        st.markdown("#### Target Rule Code Blocks")
        for i, code_block in enumerate(result["converted_code_blocks"], 1):
            st.write(f"**Code Block {i}:**")
            st.code(code_block, language="python")


def display_execution_context(result: Dict[str, Any]):
    """Display execution context"""
    st.markdown("### 📊 Execution Context Details")

    if not (
        result.get("source_execution_context")
        and result.get("target_execution_context")
    ):
        st.info("No execution context information available")
        return

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### Source Rule Execution Context")
        source_context = result["source_execution_context"]
        with st.expander("View Source Rule Execution Context", expanded=False):
            for key, value in source_context.items():
                if key.endswith("_output"):
                    st.write(f"**{key}:**")
                    if isinstance(value, list) and len(value) > 0:
                        st.json(value[0] if isinstance(value[0], dict) else value)
                    else:
                        st.json(value)
                elif key.endswith("_code"):
                    st.write(f"**{key}:**")
                    st.code(value, language="python")

    with col2:
        st.markdown("#### Target Rule Execution Context")
        target_context = result["target_execution_context"]
        with st.expander("View Target Rule Execution Context", expanded=False):
            for key, value in target_context.items():
                if key.endswith("_output"):
                    st.write(f"**{key}:**")
                    if isinstance(value, list) and len(value) > 0:
                        st.json(value[0] if isinstance(value[0], dict) else value)
                    else:
                        st.json(value)
                elif key.endswith("_code"):
                    st.write(f"**{key}:**")
                    st.code(value, language="python")


def display_optimization_suggestions(result: Dict[str, Any]):
    """Display optimization suggestions"""
    st.markdown("### 💡 Optimization Suggestions")

    suggestions = result.get("optimization_suggestions", [])
    if not suggestions:
        st.info("No optimization suggestions available")
        return

    for i, suggestion in enumerate(suggestions, 1):
        st.write(f"**{i}.** {suggestion}")


def display_optimized_rule(result: Dict[str, Any], source_rule: str, target_rule: str):
    """Display optimized rule"""
    st.markdown("### 🎯 Rule Comparison")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### Original Target Rule")
        st.code(target_rule, language="text")

    with col2:
        st.markdown("#### Optimized Target Rule")
        # Here we can add improved rules generated based on optimization suggestions
        # Currently showing original rule, can be extended later
        st.code(target_rule, language="text")
        st.info(
            "💡 The optimized rule will be improved based on optimization suggestions"
        )


if __name__ == "__main__":
    page_semantic_optimization_test()
