import streamlit as st
import json
from src.core import RuleConverter, generate_ir, analyze_rule, generate_rule_from_ir
from src.core.rule_optimizer import SyntaxRuleOptimizer, SemanticRuleOptimizer
from src.utils.conversion_logger import conversion_logger


def page_rule_conversion(model, title="RuleCon"):
    """Rule Conversion page with IR-based conversion and optimization"""
    st.title(title)
    # st.write(
    #     "Convert security rules between different SIEM platforms using Intermediate Representation (IR) and optimize the results."
    # )

    # Input the rule content
    rule_content = st.text_area(
        "Enter Rule Content:",
        placeholder="Paste your rule content here...",
        height=200,
        help="Paste the source rule content that you want to convert",
    )

    # Two dropdowns for source and target rule types
    col1, col2 = st.columns(2)

    with col1:
        source_rule_type = st.selectbox(
            "Source Rule Type:",
            [
                "Splunk",
                "Microsoft Sentinel",
                "IBM QRadar",
                "Google Chronicle",
                "RSA NetWitness",
            ],
            key="source_rule_type_selector",
            help="Select the type of the source rule",
        )

    with col2:
        target_rule_type = st.selectbox(
            "Target Rule Type:",
            [
                "Splunk",
                "Microsoft Sentinel",
                "IBM QRadar",
                "Google Chronicle",
                "RSA NetWitness",
            ],
            key="target_rule_type_selector",
            help="Select the target rule type for conversion",
        )

    # Check if source and target types are the same
    if source_rule_type == target_rule_type:
        st.warning(
            "⚠️ Source and target rule types cannot be the same. Please select different rule types."
        )
        # Disable the convert button when types are the same
        convert_disabled = True
    else:
        convert_disabled = False

    # Optional fields for conversion
    required_fields = st.text_area(
        "Additional Fields (Optional):",
        placeholder="List any additional fields needed for conversion...",
        help="Specify any additional fields or parameters needed for the conversion",
    )

    # Conversion options
    st.subheader("Conversion Options")
    col1, col2, col3 = st.columns(3)

    with col1:
        use_ir = st.checkbox(
            "Use IR-based Conversion",
            value=True,
            help="Convert through Intermediate Representation for better accuracy",
        )

    with col2:
        use_analysis = st.checkbox(
            "Use Rule Analysis",
            value=True,
            help="Analyze the source rule before conversion",
        )

    with col3:
        enable_optimization = st.checkbox(
            "Enable Rule Optimization",
            value=True,
            help="Optimize the converted rule using AI-powered optimization",
        )

    if st.button("Convert Rule", disabled=convert_disabled, type="primary"):
        if rule_content:
            try:
                # Start conversion logging
                conversion_id = conversion_logger.start_conversion(
                    source_rule_type=source_rule_type,
                    target_rule_type=target_rule_type,
                    original_rule=rule_content,
                )

                # Initialize progress tracking
                progress_bar = st.progress(0)
                status_text = st.empty()

                # Step 1: Rule Analysis (if enabled)
                rule_analysis = None
                if use_analysis:
                    status_text.text("📋 Step 1: Analyzing source rule...")
                    progress_bar.progress(0.1)

                    with st.expander("View Rule Analysis", expanded=True):
                        rule_analysis = analyze_rule(rule_content, model)
                        st.markdown(rule_analysis)

                        # Log rule analysis step
                        conversion_logger.log_rule_analysis_step(
                            step_name="rule_analysis",
                            input_content=rule_content,
                            output_content=rule_analysis,
                            metadata={
                                "source_rule_type": source_rule_type,
                                "model": model,
                            },
                        )

                # Step 2: IR Generation (if enabled)
                ir_result = None
                if use_ir:
                    status_text.text(
                        "🔧 Step 2: Generating Intermediate Representation..."
                    )
                    progress_bar.progress(0.3)

                    with st.expander("View IR Generation", expanded=True):
                        ir_result = generate_ir(
                            rule_content,
                            model,
                            rule_type=source_rule_type,
                            rule_analysis=rule_analysis,
                        )

                        if isinstance(ir_result, dict) and "rule_name" in ir_result:
                            st.success("✅ IR generated successfully!")

                            # Log IR generation step
                            conversion_logger.log_ir_generation_step(
                                step_name="ir_generation",
                                input_rule=rule_content,
                                generated_ir=json.dumps(ir_result, indent=2),
                                metadata={
                                    "source_rule_type": source_rule_type,
                                    "model": model,
                                    "rule_analysis_used": rule_analysis is not None,
                                },
                            )

                            # Log final IR
                            conversion_logger.log_final_ir(
                                json.dumps(ir_result, indent=2)
                            )

                            # Display IR summary
                            col1, col2 = st.columns([2, 1])
                            with col1:
                                st.json(ir_result)
                            with col2:
                                st.write("**IR Summary:**")
                                st.write(
                                    f"**Rule Name:** {ir_result.get('rule_name', 'N/A')}"
                                )
                                st.write(
                                    f"**Data Source:** {ir_result.get('data_source', 'N/A')}"
                                )
                                st.write(
                                    f"**Event Type:** {ir_result.get('event_type', 'N/A')}"
                                )
                                st.write(
                                    f"**Steps Count:** {len(ir_result.get('steps', []))}"
                                )
                        else:
                            st.error("❌ Failed to generate IR")
                            st.write(ir_result)
                            return
                else:
                    # Skip IR generation
                    status_text.text("⏭️ Skipping IR generation...")
                    progress_bar.progress(0.3)

                # Step 3: Rule Conversion
                status_text.text("🔄 Step 3: Converting rule...")
                progress_bar.progress(0.5)

                if use_ir and ir_result:
                    # Use IR-based conversion
                    converted_rule = generate_rule_from_ir(
                        ir_result, target_rule_type, model
                    )
                else:
                    # Use traditional conversion
                    converted_rule = RuleConverter.convert_rule(
                        rule_content,
                        target_rule_type,
                        source_type=source_rule_type,
                        additional_fields=required_fields,
                        model=model,
                    )["rule"]

                progress_bar.progress(0.7)

                # Step 4: Rule Optimization (if enabled)
                optimized_rule = converted_rule
                optimization_result = None
                semantic_optimization_result = None

                if enable_optimization:
                    status_text.text("🚀 Step 4: Optimizing converted rule...")
                    progress_bar.progress(0.8)

                    try:
                        with st.expander("View Optimization Process", expanded=True):
                            # Initialize rule optimizer
                            optimizer = SyntaxRuleOptimizer(model=model)

                            # Generate optimization todo list
                            st.write("**Generating optimization tasks...**")
                            todo_list = optimizer.generate_optimization_todo_list(
                                converted_rule, target_rule_type
                            )

                            if todo_list:
                                st.success(
                                    f"✅ Generated {todo_list.total_tasks} optimization tasks"
                                )

                                # Display optimization tasks
                                st.write("**Optimization Tasks:**")
                                for i, task in enumerate(todo_list.tasks, 1):
                                    st.write(
                                        f"{i}. **{task.task_name}**: {task.description}"
                                    )
                                    st.write(f"   Keyword: {task.search_keyword}")

                                # Complete optimization tasks
                                st.write("**Executing optimization tasks...**")
                                optimization_result = (
                                    optimizer.complete_all_optimization_tasks(
                                        todo_list, converted_rule
                                    )
                                )

                                if optimization_result:
                                    optimized_rule = (
                                        optimization_result.final_optimized_rule
                                    )
                                    st.success(
                                        f"✅ Syntax optimization completed! Score: {optimization_result.overall_semantic_preservation_score:.2f}"
                                    )

                                    # Display optimization summary
                                    st.write("**Syntax Optimization Summary:**")
                                    st.markdown(
                                        optimization_result.optimization_summary
                                    )
                                else:
                                    st.warning(
                                        "⚠️ Syntax optimization failed, using original converted rule"
                                    )
                            else:
                                st.warning("⚠️ Failed to generate optimization tasks")
                    except Exception as e:
                        st.warning(
                            f"⚠️ Syntax optimization failed: {str(e)}, using original converted rule"
                        )

                    # Step 5: Semantic Optimization (if IR is available and syntax optimization succeeded)
                    if use_ir and ir_result and optimization_result:
                        status_text.text(
                            "🧠 Step 5: Performing semantic optimization..."
                        )
                        progress_bar.progress(0.9)

                        try:
                            with st.expander(
                                "View Semantic Optimization Process", expanded=True
                            ):
                                st.write("**Starting semantic optimization...**")

                                # Initialize semantic optimizer
                                semantic_optimizer = SemanticRuleOptimizer(model=model)

                                # Generate converted rule IR for comparison
                                st.write("**Generating converted rule IR...**")
                                converted_ir = generate_ir(
                                    optimized_rule, model, target_rule_type
                                )

                                if converted_ir and isinstance(converted_ir, dict):
                                    st.success(
                                        "✅ Converted rule IR generated successfully"
                                    )

                                    # Perform semantic optimization
                                    st.write("**Analyzing semantic equivalence...**")
                                    semantic_optimization_result = (
                                        semantic_optimizer.optimize_rule_semantics(
                                            original_rule=rule_content,
                                            converted_rule=optimized_rule,
                                            original_ir=ir_result,
                                            converted_ir=converted_ir,
                                            source_rule_type=source_rule_type,
                                            target_rule_type=target_rule_type,
                                        )
                                    )

                                    if semantic_optimization_result["success"]:
                                        semantic_score = semantic_optimization_result[
                                            "semantic_equivalence_score"
                                        ]
                                        st.success(
                                            f"✅ Semantic optimization completed! Score: {semantic_score:.2f}"
                                        )

                                        # Display semantic optimization results
                                        st.write("**Semantic Optimization Results:**")

                                        # Show test results
                                        comparison = semantic_optimization_result[
                                            "comparison_results"
                                        ]
                                        col1, col2, col3 = st.columns(3)
                                        with col1:
                                            st.metric(
                                                "Total Tests", comparison["total_tests"]
                                            )
                                        with col2:
                                            st.metric("Matches", comparison["matches"])
                                        with col3:
                                            st.metric(
                                                "Equivalence Score",
                                                f"{semantic_score:.2f}",
                                            )

                                        # Show optimization suggestions
                                        suggestions = semantic_optimization_result[
                                            "optimization_suggestions"
                                        ]
                                        if suggestions:
                                            st.write("**Optimization Suggestions:**")
                                            for i, suggestion in enumerate(
                                                suggestions, 1
                                            ):
                                                st.write(f"{i}. {suggestion}")

                                        # Show test data sample
                                        if semantic_optimization_result[
                                            "test_log_data"
                                        ]:
                                            st.write("**Generated Test Data Sample:**")
                                            for i, log_entry in enumerate(
                                                semantic_optimization_result[
                                                    "test_log_data"
                                                ][:3],
                                                1,
                                            ):
                                                try:
                                                    log_data = json.loads(log_entry)
                                                    st.json(log_data)
                                                except:
                                                    st.text(log_entry)

                                        # Update the final rule if semantic optimization suggests changes
                                        if (
                                            semantic_score < 0.8
                                        ):  # If semantic score is low, keep the syntax optimized version
                                            st.warning(
                                                f"⚠️ Low semantic equivalence score ({semantic_score:.2f}). Consider reviewing the conversion."
                                            )
                                        else:
                                            st.success(
                                                f"✅ High semantic equivalence score ({semantic_score:.2f}). Rule conversion is semantically accurate."
                                            )

                                    else:
                                        st.warning(
                                            f"⚠️ Semantic optimization failed: {semantic_optimization_result.get('error', 'Unknown error')}"
                                        )

                                else:
                                    st.warning(
                                        f"⚠️ Failed to generate converted rule IR for semantic analysis. IR content: {converted_ir}"
                                    )

                        except Exception as e:
                            st.warning(f"⚠️ Semantic optimization failed: {str(e)}")
                            semantic_optimization_result = None

                # Complete progress
                progress_bar.progress(1.0)
                status_text.text("✅ Conversion completed!")

                # Finish conversion logging
                log_file_path = conversion_logger.finish_conversion(
                    final_rule=optimized_rule,
                    success=True,
                    total_tasks_completed=(
                        optimization_result.total_tasks_completed
                        if optimization_result
                        else 0
                    ),
                    overall_semantic_score=(
                        optimization_result.overall_semantic_preservation_score
                        if optimization_result
                        else 1.0
                    ),
                )

                if log_file_path:
                    st.info(f"📝 Conversion log saved to: {log_file_path}")

                # Display final results
                st.success("✅ Rule Conversion Completed Successfully!")

                # Create tabs for different views
                tab1, tab2, tab3, tab4 = st.tabs(
                    [
                        "Converted Rule",
                        "IR Details",
                        "Syntax Optimization",
                        "Semantic Optimization",
                    ]
                )

                with tab1:
                    st.subheader("Final Converted Rule")
                    if enable_optimization and optimization_result:
                        st.write("**Optimized Rule:**")
                        st.markdown(f"```\n{optimized_rule}\n```")

                        # Show comparison
                        st.write("**Comparison:**")
                        col1, col2 = st.columns(2)
                        with col1:
                            st.write("**Before Optimization:**")
                            st.markdown(f"```\n{converted_rule}\n```")
                        with col2:
                            st.write("**After Optimization:**")
                            st.markdown(f"```\n{optimized_rule}\n```")
                    else:
                        st.markdown(f"```\n{converted_rule}\n```")

                with tab2:
                    if ir_result and use_ir:
                        st.subheader("Intermediate Representation")
                        st.json(ir_result)

                        # IR validation
                        st.write("**IR Validation:**")
                        validation_results = validate_ir_structure(ir_result)
                        for field, status in validation_results.items():
                            if status:
                                st.success(f"✅ {field}: Valid")
                            else:
                                st.error(f"❌ {field}: Invalid")
                    else:
                        st.info("IR generation was not enabled for this conversion.")

                with tab3:
                    if enable_optimization and optimization_result:
                        st.subheader("Syntax Optimization Results")

                        # Overall metrics
                        col1, col2, col3 = st.columns(3)
                        with col1:
                            st.metric(
                                "Total Tasks", optimization_result.total_tasks_completed
                            )
                        with col2:
                            st.metric(
                                "Semantic Score",
                                f"{optimization_result.overall_semantic_preservation_score:.2f}",
                            )
                        with col3:
                            st.metric("Rule Type", optimization_result.rule_type)

                        # Detailed task results
                        st.write("**Task Results:**")
                        for i, task_result in enumerate(
                            optimization_result.task_results, 1
                        ):
                            with st.expander(f"Task {i}: {task_result.task_name}"):
                                st.write(
                                    f"**Semantic Score:** {task_result.semantic_preservation_score:.2f}"
                                )
                                st.write(
                                    f"**Explanation:** {task_result.optimization_explanation}"
                                )
                                st.write(
                                    f"**Keyword Used:** {task_result.search_keyword_used}"
                                )

                                # Show rule before and after optimization for this task
                                if hasattr(task_result, "original_rule") and hasattr(
                                    task_result, "optimized_rule"
                                ):
                                    st.write("**Rule Comparison:**")
                                    col1, col2 = st.columns(2)

                                    with col1:
                                        st.write("**Before Optimization:**")
                                        st.code(
                                            task_result.original_rule, language="text"
                                        )

                                    with col2:
                                        st.write("**After Optimization:**")
                                        st.code(
                                            task_result.optimized_rule, language="text"
                                        )
                    else:
                        st.info(
                            "Syntax optimization was not enabled for this conversion."
                        )

                with tab4:
                    if (
                        semantic_optimization_result
                        and semantic_optimization_result["success"]
                    ):
                        st.subheader("Semantic Optimization Results")

                        # Overall semantic metrics
                        comparison = semantic_optimization_result["comparison_results"]
                        col1, col2, col3, col4 = st.columns(4)

                        with col1:
                            st.metric(
                                "Semantic Score",
                                f"{semantic_optimization_result['semantic_equivalence_score']:.2f}",
                            )
                        with col2:
                            comparison_method = comparison.get(
                                "comparison_method", "unknown"
                            )
                            if comparison_method == "llm_comparison":
                                st.metric("Comparison Method", "AI Analysis")
                            else:
                                st.metric(
                                    "Comparison Method",
                                    comparison_method.replace("_", " ").title(),
                                )
                        with col3:
                            st.metric(
                                "Matches",
                                f"{comparison['matches']}",
                            )
                        with col4:
                            st.metric(
                                "Mismatches",
                                f"{comparison['mismatches']}",
                            )

                        # Detailed comparison results
                        st.write("**Comparison Analysis:**")
                        col1, col2 = st.columns(2)

                        with col1:
                            st.write("**Basic Metrics:**")
                            st.write(f"- Total Tests: {comparison['total_tests']}")
                            st.write(f"- Matches: {comparison['matches']}")
                            st.write(f"- Mismatches: {comparison['mismatches']}")
                            st.write(
                                f"- Equivalence Score: {semantic_optimization_result['semantic_equivalence_score']:.2f}"
                            )

                        with col2:
                            st.write("**Comparison Details:**")
                            comparison_method = comparison.get(
                                "comparison_method", "unknown"
                            )
                            if comparison_method == "llm_comparison":
                                st.write("- Method: AI Analysis")
                                st.write(
                                    "- Rule Type: {source_rule_type} → {target_rule_type}"
                                )

                                # Show LLM analysis if available
                                if (
                                    "llm_analysis" in comparison
                                    and comparison["llm_analysis"]
                                ):
                                    st.write("**AI Analysis:**")
                                    st.write(comparison["llm_analysis"])

                                if (
                                    "llm_reasoning" in comparison
                                    and comparison["llm_reasoning"]
                                ):
                                    with st.expander(
                                        "View AI Reasoning", expanded=False
                                    ):
                                        st.write(comparison["llm_reasoning"])
                            else:
                                st.write(f"- Method: {comparison_method}")
                                st.write(
                                    f"- Rule Type: {source_rule_type} → {target_rule_type}"
                                )

                            # Show result types if available
                            if (
                                "original_results" in comparison
                                and "converted_results" in comparison
                            ):
                                orig_type = type(
                                    comparison["original_results"]
                                ).__name__
                                conv_type = type(
                                    comparison["converted_results"]
                                ).__name__
                                st.write(f"- Original Output Type: {orig_type}")
                                st.write(f"- Converted Output Type: {conv_type}")

                        # Optimization suggestions and optimized rule
                        suggestions = semantic_optimization_result.get(
                            "optimization_suggestions", []
                        )
                        optimized_rule = semantic_optimization_result.get(
                            "optimized_rule", ""
                        )

                        if suggestions:
                            st.write("**Optimization Suggestions:**")
                            for i, suggestion in enumerate(suggestions, 1):
                                st.write(f"{i}. {suggestion}")

                        # Show optimized rule if available
                        if optimized_rule and optimized_rule != rule_content:
                            st.write("**Optimized Rule:**")
                            st.code(optimized_rule, language="yaml")

                            # Add download button for optimized rule
                            st.download_button(
                                label="Download Optimized Rule",
                                data=optimized_rule,
                                file_name=f"optimized_{target_rule_type.lower()}_rule.yml",
                                mime="text/yaml",
                            )
                        elif optimized_rule:
                            st.info(
                                "Optimized rule is identical to the converted rule - no changes were needed."
                            )

                        # Execution results comparison
                        if (
                            "original_results" in comparison
                            and "converted_results" in comparison
                        ):
                            st.write("**Execution Results Comparison:**")

                            # Show result types and sample data
                            col1, col2 = st.columns(2)

                            with col1:
                                st.write("**Original Rule Results:**")
                                orig_results = comparison["original_results"]
                                st.write(f"Type: {type(orig_results).__name__}")
                                if (
                                    isinstance(orig_results, list)
                                    and len(orig_results) > 0
                                ):
                                    st.write(f"Count: {len(orig_results)}")
                                    with st.expander(
                                        "View Sample Results", expanded=False
                                    ):
                                        for i, result in enumerate(orig_results[:3], 1):
                                            st.write(f"**Result {i}:**")
                                            if isinstance(result, (dict, list)):
                                                st.json(result)
                                            else:
                                                st.text(str(result))
                                else:
                                    st.text(str(orig_results))

                            with col2:
                                st.write("**Converted Rule Results:**")
                                conv_results = comparison["converted_results"]
                                st.write(f"Type: {type(conv_results).__name__}")
                                if (
                                    isinstance(conv_results, list)
                                    and len(conv_results) > 0
                                ):
                                    st.write(f"Count: {len(conv_results)}")
                                    with st.expander(
                                        "View Sample Results", expanded=False
                                    ):
                                        for i, result in enumerate(conv_results[:3], 1):
                                            st.write(f"**Result {i}:**")
                                            if isinstance(result, (dict, list)):
                                                st.json(result)
                                            else:
                                                st.text(str(result))
                                else:
                                    st.text(str(conv_results))

                        # Generated test data
                        if semantic_optimization_result.get("test_log_data"):
                            st.write("**Generated Test Data:**")
                            with st.expander("View Test Log Data", expanded=False):
                                for i, log_entry in enumerate(
                                    semantic_optimization_result["test_log_data"][:5], 1
                                ):
                                    try:
                                        log_data = json.loads(log_entry)
                                        st.write(f"**Test {i}:**")
                                        st.json(log_data)
                                    except:
                                        st.write(f"**Test {i}:**")
                                        st.text(log_entry)

                        # Code blocks comparison
                        if (
                            semantic_optimization_result["original_code_blocks"]
                            and semantic_optimization_result["converted_code_blocks"]
                        ):
                            st.write("**Generated Code Blocks:**")
                            col1, col2 = st.columns(2)

                            with col1:
                                st.write("**Original Rule Code Blocks:**")
                                for i, code_block in enumerate(
                                    semantic_optimization_result[
                                        "original_code_blocks"
                                    ][:3],
                                    1,
                                ):
                                    st.write(f"**Block {i}:**")
                                    st.code(code_block, language="python")

                            with col2:
                                st.write("**Converted Rule Code Blocks:**")
                                for i, code_block in enumerate(
                                    semantic_optimization_result[
                                        "converted_code_blocks"
                                    ][:3],
                                    1,
                                ):
                                    st.write(f"**Block {i}:**")
                                    st.code(code_block, language="python")

                        # Execution Context Details
                        if semantic_optimization_result.get(
                            "source_execution_context"
                        ) and semantic_optimization_result.get(
                            "target_execution_context"
                        ):
                            st.write("**Execution Context Details:**")
                            col1, col2 = st.columns(2)

                            with col1:
                                st.write("**Source Rule Execution Context:**")
                                source_context = semantic_optimization_result[
                                    "source_execution_context"
                                ]
                                with st.expander(
                                    "View Source Execution Context", expanded=False
                                ):
                                    for key, value in source_context.items():
                                        if key.endswith("_output"):
                                            st.write(f"**{key}:**")
                                            if (
                                                isinstance(value, list)
                                                and len(value) > 0
                                            ):
                                                # Show first item if it's a list
                                                st.json(
                                                    value[0]
                                                    if isinstance(value[0], dict)
                                                    else value
                                                )
                                            else:
                                                st.json(value)
                                        elif key.endswith("_code"):
                                            st.write(f"**{key}:**")
                                            st.code(value, language="python")

                            with col2:
                                st.write("**Target Rule Execution Context:**")
                                target_context = semantic_optimization_result[
                                    "target_execution_context"
                                ]
                                with st.expander(
                                    "View Target Execution Context", expanded=False
                                ):
                                    for key, value in target_context.items():
                                        if key.endswith("_output"):
                                            st.write(f"**{key}:**")
                                            if (
                                                isinstance(value, list)
                                                and len(value) > 0
                                            ):
                                                # Show first item if it's a list
                                                st.json(
                                                    value[0]
                                                    if isinstance(value[0], dict)
                                                    else value
                                                )
                                            else:
                                                st.json(value)
                                        elif key.endswith("_code"):
                                            st.write(f"**{key}:**")
                                            st.code(value, language="python")

                    elif (
                        semantic_optimization_result
                        and not semantic_optimization_result["success"]
                    ):
                        st.error(
                            f"❌ Semantic optimization failed: {semantic_optimization_result.get('error', 'Unknown error')}"
                        )

                    else:
                        st.info(
                            "Semantic optimization was not performed. Enable IR generation and syntax optimization to use semantic optimization."
                        )

                # Download options
                st.subheader("💾 Download Results")
                col1, col2 = st.columns(2)

                with col1:
                    # Download converted rule
                    if enable_optimization and optimization_result:
                        rule_content = optimized_rule
                        filename = f"converted_{target_rule_type.lower().replace(' ', '_')}_optimized.txt"
                    else:
                        rule_content = converted_rule
                        filename = f"converted_{target_rule_type.lower().replace(' ', '_')}.txt"

                    st.download_button(
                        label="Download Converted Rule",
                        data=rule_content,
                        file_name=filename,
                        mime="text/plain",
                    )

                with col2:
                    # Download IR if available
                    if ir_result and use_ir:
                        ir_json = json.dumps(ir_result, indent=2)
                        st.download_button(
                            label="Download IR as JSON",
                            data=ir_json,
                            file_name=f"{ir_result.get('rule_name', 'rule')}_ir.json",
                            mime="application/json",
                        )

            except Exception as e:
                # Log conversion failure
                conversion_logger.finish_conversion(
                    final_rule="", success=False, error_message=str(e)
                )

                st.error(f"❌ Conversion failed: {str(e)}")
                st.exception(e)
        else:
            st.warning("⚠️ Please enter rule content to convert.")


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
