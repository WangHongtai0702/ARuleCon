import json

from src.core.rule_types import SplunkRule, SentinelRule
from src.llms.client import client
from src.llms.prompts import PREPROCESSING_PROMPT


def extract_info_from_pipe(pipe_str: str, model: str) -> dict:
    sys_prompt = PREPROCESSING_PROMPT
    user_prompt = f"""
    The following is a part of a Splunk rule:
    {pipe_str}
    """

    # 检查client是否可用
    if not client:
        return {"operation_type": "unknown", "input_fields": [], "output_fields": []}

    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": sys_prompt},
            {"role": "user", "content": user_prompt},
        ],
        response_format={"type": "json_object"},
    )
    return json.loads(response.choices[0].message.content)


def analyze_rule(rule_content: str, model: str) -> str:
    """Analyze and understand a rule using LLM"""
    from src.llms.prompts import RULE_ANALYSIS_PROMPT

    # 检查client是否可用
    if not client:
        return "Error: OpenAI client not available. Please check your API key configuration."

    sys_prompt = RULE_ANALYSIS_PROMPT
    user_prompt = f"""
    Splunk Rule:
    {rule_content}
    """

    messages = [
        {"role": "system", "content": sys_prompt},
        {"role": "user", "content": user_prompt},
    ]

    try:
        response = client.chat.completions.create(
            model=model, messages=messages, temperature=0.1
        )

        return response.choices[0].message.content

    except Exception as e:
        return f"Error analyzing rule: {str(e)}"


def generate_rule_from_ir(ir_data: dict, target_rule_type: str, model: str) -> str:
    """Generate a rule from IR data for the specified target type"""
    from src.llms.prompts import (
        IR_TO_SPLUNK_PROMPT,
        IR_TO_SENTINEL_PROMPT,
        IR_TO_QRADAR_PROMPT,
        IR_TO_CHRONICLE_YARAL_PROMPT,
        IR_TO_NETWITNESS_ESA_PROMPT,
    )

    # 检查client是否可用
    if not client:
        return "Error: OpenAI client not available. Please check your API key configuration."

    # 根据目标规则类型选择对应的prompt
    target_prompt = ""
    if target_rule_type:
        target_type_lower = target_rule_type.lower()
        if "splunk" in target_type_lower:
            target_prompt = IR_TO_SPLUNK_PROMPT
        elif "sentinel" in target_type_lower:
            target_prompt = IR_TO_SENTINEL_PROMPT
        elif "qradar" in target_type_lower or "aql" in target_type_lower:
            target_prompt = IR_TO_QRADAR_PROMPT
        elif "chronicle" in target_type_lower or "yara" in target_type_lower:
            target_prompt = IR_TO_CHRONICLE_YARAL_PROMPT
        elif "netwitness" in target_type_lower or "esa" in target_type_lower:
            target_prompt = IR_TO_NETWITNESS_ESA_PROMPT
        else:
            return f"Error: Unsupported target rule type: {target_rule_type}"

    # 构建system prompt
    sys_prompt = target_prompt

    # 构建用户提示，包含IR数据和目标类型信息
    user_prompt = f"""
    ## Target Rule Type:
    {target_rule_type}

    ## Intermediate Representation (IR):
    ```json
    {json.dumps(ir_data, indent=2)}
    ```

    ## Conversion Instructions:
    1. Analyze the IR structure and understand the detection logic
    2. Map each IR step to the appropriate syntax for {target_rule_type}
    3. Generate a complete and valid rule in {target_rule_type} format
    4. Ensure the generated rule maintains the same detection logic as the IR
    5. Follow the best practices for {target_rule_type}

    Now convert the IR to a {target_rule_type} rule:
    """

    messages = [
        {"role": "system", "content": sys_prompt},
        {"role": "user", "content": user_prompt},
    ]

    try:
        response = client.chat.completions.create(
            model=model, messages=messages, temperature=0.1
        )

        generated_rule = response.choices[0].message.content

        # 清理输出，移除可能的markdown代码块标记
        if "```" in generated_rule:
            import re

            # 尝试多种代码块模式
            patterns = [
                r"```(?:spl|kql|sql|yara-l|yara|esa)?\n(.*?)\n```",  # 带语言标记的代码块
                r"```\n(.*?)\n```",  # 不带语言标记的代码块
                r"```(.*?)```",  # 单行代码块
            ]

            for pattern in patterns:
                match = re.search(pattern, generated_rule, re.DOTALL)
                if match:
                    generated_rule = match.group(1).strip()
                    break

        return generated_rule

    except Exception as e:
        return f"Error generating {target_rule_type} rule: {str(e)}"


def generate_ir(
    rule_content: str, model: str, rule_type: str = None, rule_analysis: str = None
) -> dict:
    """Generate Intermediate Representation (IR) from a rule"""
    from src.llms.prompts import (
        RULE_TO_IR_PROMPT,
        SPLUNK_IR_GUIDE,
        SENTINEL_IR_GUIDE,
        QRADAR_AQL_IR_GUIDE,
        CHRONICLE_YARAL_IR_GUIDE,
        NETWITNESS_ESA_IR_GUIDE,
    )

    # 检查client是否可用
    if not client:
        return {
            "rule_name": "error_rule",
            "description": "Error: OpenAI client not available. Please check your API key configuration.",
            "data_source": "unknown",
            "event_type": "error",
            "steps": [],
        }

    # 根据规则类型选择对应的指导prompt
    rule_type_guide = ""
    if rule_type:
        rule_type_lower = rule_type.lower()
        if "splunk" in rule_type_lower:
            rule_type_guide = SPLUNK_IR_GUIDE
        elif "sentinel" in rule_type_lower:
            rule_type_guide = SENTINEL_IR_GUIDE
        elif "qradar" in rule_type_lower or "aql" in rule_type_lower:
            rule_type_guide = QRADAR_AQL_IR_GUIDE
        elif "chronicle" in rule_type_lower or "yara" in rule_type_lower:
            rule_type_guide = CHRONICLE_YARAL_IR_GUIDE
        elif "netwitness" in rule_type_lower or "esa" in rule_type_lower:
            rule_type_guide = NETWITNESS_ESA_IR_GUIDE

    # 拼接system prompt，包含通用指导和特定规则类型指导
    if rule_type_guide:
        sys_prompt = RULE_TO_IR_PROMPT + "\n\n" + rule_type_guide
    else:
        sys_prompt = RULE_TO_IR_PROMPT

    # 构建用户提示，可选择性地包含规则类型和规则分析
    if rule_analysis:
        user_prompt = f"""
        ## Rule Type:
        {rule_type or "Unknown"}
        
        ## Rule Analysis:
        {rule_analysis}
        
        ## Original Rule:
        {rule_content}
        
        Based on the above analysis and the original rule, generate the IR.
        """
    else:
        user_prompt = f"""
        ## Rule Type:
        {rule_type or "Unknown"}
        
        Rule to convert:
        {rule_content}
        """

    messages = [
        {"role": "system", "content": sys_prompt},
        {"role": "user", "content": user_prompt},
    ]

    try:
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=0.1,
            response_format={"type": "json_object"},
        )

        # 解析JSON响应
        ir_result = json.loads(response.choices[0].message.content)

        # 验证IR格式
        required_fields = [
            "rule_name",
            "description",
            "data_source",
            "event_type",
            "steps",
        ]
        for field in required_fields:
            if field not in ir_result:
                raise ValueError(f"Missing required field: {field}")

        # 验证steps格式
        if not isinstance(ir_result["steps"], list):
            raise ValueError("Steps must be a list")

        for step in ir_result["steps"]:
            if not isinstance(step, dict):
                raise ValueError("Each step must be a dictionary")
            step_fields = ["action", "params", "explanation"]
            for field in step_fields:
                if field not in step:
                    raise ValueError(f"Missing required field in step: {field}")

        return ir_result

    except Exception as e:
        return {
            "rule_name": "error_rule",
            "description": f"Error generating IR: {str(e)}",
            "data_source": "unknown",
            "event_type": "error",
            "steps": [],
        }


class RuleConverter:
    # Registry for all supported conversion methods
    _conversion_map = {}

    @classmethod
    def register(cls, source_type, target_type):
        def decorator(func):
            cls._conversion_map[(source_type.lower(), target_type.lower())] = func
            return func

        return decorator

    @classmethod
    def convert_rule(
        cls,
        rule_content,
        target_type,
        source_type=None,
        additional_fields=None,
        model=None,
    ):
        if not source_type or not target_type:
            raise ValueError("Both source_type and target_type must be specified.")
        key = (source_type.lower(), target_type.lower())
        if key not in cls._conversion_map:
            raise NotImplementedError(
                f"Conversion from {source_type} to {target_type} is not supported."
            )
        return {
            "rule": cls._conversion_map[key](
                rule_content, additional_fields, model=model
            )
        }


# Splunk → Sentinel 转换（使用IR中间层）
@RuleConverter.register("Splunk", "Microsoft Sentinel")
def splunk_to_sentinel(rule_content, additional_fields, model=None):
    """Convert Splunk rule to Microsoft Sentinel rule using IR as intermediate"""
    try:
        # Step 1: Generate IR from Splunk rule
        ir_result = generate_ir(rule_content, model, rule_type="Splunk")

        # Step 2: Generate Sentinel rule from IR
        sentinel_rule = generate_rule_from_ir(ir_result, "Microsoft Sentinel", model)

        return sentinel_rule
    except Exception as e:
        return f"Error converting Splunk to Sentinel: {str(e)}"


# Splunk → Elastic 转换（使用IR中间层）
@RuleConverter.register("Splunk", "Elastic")
def splunk_to_elastic(rule_content, additional_fields, model=None):
    """Convert Splunk rule to Elastic rule using IR as intermediate"""
    try:
        # Step 1: Generate IR from Splunk rule
        ir_result = generate_ir(rule_content, model, rule_type="Splunk")

        # Step 2: Generate Elastic rule from IR
        elastic_rule = generate_rule_from_ir(ir_result, "Elastic", model)

        return elastic_rule
    except Exception as e:
        return f"Error converting Splunk to Elastic: {str(e)}"


# Splunk → Google Chronicle YARA-L 转换（使用IR中间层）
@RuleConverter.register("Splunk", "Google Chronicle YARA-L")
def splunk_to_chronicle_yaral(rule_content, additional_fields, model=None):
    """Convert Splunk rule to Google Chronicle YARA-L rule using IR as intermediate"""
    try:
        # Step 1: Generate IR from Splunk rule
        ir_result = generate_ir(rule_content, model, rule_type="Splunk")

        # Step 2: Generate YARA-L rule from IR
        yaral_rule = generate_rule_from_ir(ir_result, "Google Chronicle YARA-L", model)

        return yaral_rule
    except Exception as e:
        return f"Error converting Splunk to YARA-L: {str(e)}"


# Microsoft Sentinel → Splunk 转换（使用IR中间层）
@RuleConverter.register("Microsoft Sentinel", "Splunk")
def sentinel_to_splunk(rule_content, additional_fields, model=None):
    """Convert Microsoft Sentinel rule to Splunk rule using IR as intermediate"""
    try:
        # Step 1: Generate IR from Sentinel rule
        ir_result = generate_ir(rule_content, model, rule_type="Microsoft Sentinel")

        # Step 2: Generate Splunk rule from IR
        splunk_rule = generate_rule_from_ir(ir_result, "Splunk", model)

        return splunk_rule
    except Exception as e:
        return f"Error converting Sentinel to Splunk: {str(e)}"


# Microsoft Sentinel → Elastic 转换（使用IR中间层）
@RuleConverter.register("Microsoft Sentinel", "Elastic")
def sentinel_to_elastic(rule_content, additional_fields, model=None):
    """Convert Microsoft Sentinel rule to Elastic rule using IR as intermediate"""
    try:
        # Step 1: Generate IR from Sentinel rule
        ir_result = generate_ir(rule_content, model, rule_type="Microsoft Sentinel")

        # Step 2: Generate Elastic rule from IR
        elastic_rule = generate_rule_from_ir(ir_result, "Elastic", model)

        return elastic_rule
    except Exception as e:
        return f"Error converting Sentinel to Elastic: {str(e)}"


# Microsoft Sentinel → Google Chronicle YARA-L 转换（使用IR中间层）
@RuleConverter.register("Microsoft Sentinel", "Google Chronicle YARA-L")
def sentinel_to_chronicle_yaral(rule_content, additional_fields, model=None):
    """Convert Microsoft Sentinel rule to Google Chronicle YARA-L rule using IR as intermediate"""
    try:
        # Step 1: Generate IR from Sentinel rule
        ir_result = generate_ir(rule_content, model, rule_type="Microsoft Sentinel")

        # Step 2: Generate YARA-L rule from IR
        yaral_rule = generate_rule_from_ir(ir_result, "Google Chronicle YARA-L", model)

        return yaral_rule
    except Exception as e:
        return f"Error converting Sentinel to YARA-L: {str(e)}"


# IBM QRadar AQL → Splunk 转换（使用IR中间层）
@RuleConverter.register("IBM QRadar AQL", "Splunk")
def qradar_to_splunk(rule_content, additional_fields, model=None):
    """Convert IBM QRadar AQL rule to Splunk rule using IR as intermediate"""
    try:
        # Step 1: Generate IR from QRadar AQL rule
        ir_result = generate_ir(rule_content, model, rule_type="IBM QRadar AQL")

        # Step 2: Generate Splunk rule from IR
        splunk_rule = generate_rule_from_ir(ir_result, "Splunk", model)

        return splunk_rule
    except Exception as e:
        return f"Error converting QRadar AQL to Splunk: {str(e)}"


# IBM QRadar AQL → Microsoft Sentinel 转换（使用IR中间层）
@RuleConverter.register("IBM QRadar AQL", "Microsoft Sentinel")
def qradar_to_sentinel(rule_content, additional_fields, model=None):
    """Convert IBM QRadar AQL rule to Microsoft Sentinel rule using IR as intermediate"""
    try:
        # Step 1: Generate IR from QRadar AQL rule
        ir_result = generate_ir(rule_content, model, rule_type="IBM QRadar AQL")

        # Step 2: Generate Sentinel rule from IR
        sentinel_rule = generate_rule_from_ir(ir_result, "Microsoft Sentinel", model)

        return sentinel_rule
    except Exception as e:
        return f"Error converting QRadar AQL to Sentinel: {str(e)}"


# IBM QRadar AQL → Elastic 转换（使用IR中间层）
@RuleConverter.register("IBM QRadar AQL", "Elastic")
def qradar_to_elastic(rule_content, additional_fields, model=None):
    """Convert IBM QRadar AQL rule to Elastic rule using IR as intermediate"""
    try:
        # Step 1: Generate IR from QRadar AQL rule
        ir_result = generate_ir(rule_content, model, rule_type="IBM QRadar AQL")

        # Step 2: Generate Elastic rule from IR
        elastic_rule = generate_rule_from_ir(ir_result, "Elastic", model)

        return elastic_rule
    except Exception as e:
        return f"Error converting QRadar AQL to Elastic: {str(e)}"


# IBM QRadar AQL → Google Chronicle YARA-L 转换（使用IR中间层）
@RuleConverter.register("IBM QRadar AQL", "Google Chronicle YARA-L")
def qradar_to_chronicle_yaral(rule_content, additional_fields, model=None):
    """Convert IBM QRadar AQL rule to Google Chronicle YARA-L rule using IR as intermediate"""
    try:
        # Step 1: Generate IR from QRadar AQL rule
        ir_result = generate_ir(rule_content, model, rule_type="IBM QRadar AQL")

        # Step 2: Generate YARA-L rule from IR
        yaral_rule = generate_rule_from_ir(ir_result, "Google Chronicle YARA-L", model)

        return yaral_rule
    except Exception as e:
        return f"Error converting QRadar AQL to YARA-L: {str(e)}"


# Google Chronicle YARA-L → Splunk 转换（使用IR中间层）
@RuleConverter.register("Google Chronicle YARA-L", "Splunk")
def chronicle_yaral_to_splunk(rule_content, additional_fields, model=None):
    """Convert Google Chronicle YARA-L rule to Splunk rule using IR as intermediate"""
    try:
        # Step 1: Generate IR from YARA-L rule
        ir_result = generate_ir(
            rule_content, model, rule_type="Google Chronicle YARA-L"
        )

        # Step 2: Generate Splunk rule from IR
        splunk_rule = generate_rule_from_ir(ir_result, "Splunk", model)

        return splunk_rule
    except Exception as e:
        return f"Error converting YARA-L to Splunk: {str(e)}"


# Google Chronicle YARA-L → Microsoft Sentinel 转换（使用IR中间层）
@RuleConverter.register("Google Chronicle YARA-L", "Microsoft Sentinel")
def chronicle_yaral_to_sentinel(rule_content, additional_fields, model=None):
    """Convert Google Chronicle YARA-L rule to Microsoft Sentinel rule using IR as intermediate"""
    try:
        # Step 1: Generate IR from YARA-L rule
        ir_result = generate_ir(
            rule_content, model, rule_type="Google Chronicle YARA-L"
        )

        # Step 2: Generate Sentinel rule from IR
        sentinel_rule = generate_rule_from_ir(ir_result, "Microsoft Sentinel", model)

        return sentinel_rule
    except Exception as e:
        return f"Error converting YARA-L to Sentinel: {str(e)}"


# Google Chronicle YARA-L → Elastic 转换（使用IR中间层）
@RuleConverter.register("Google Chronicle YARA-L", "Elastic")
def chronicle_yaral_to_elastic(rule_content, additional_fields, model=None):
    """Convert Google Chronicle YARA-L rule to Elastic rule using IR as intermediate"""
    try:
        # Step 1: Generate IR from YARA-L rule
        ir_result = generate_ir(
            rule_content, model, rule_type="Google Chronicle YARA-L"
        )

        # Step 2: Generate Elastic rule from IR
        elastic_rule = generate_rule_from_ir(ir_result, "Elastic", model)

        return elastic_rule
    except Exception as e:
        return f"Error converting YARA-L to Elastic: {str(e)}"


# RSA NetWitness ESA → Splunk 转换（使用IR中间层）
@RuleConverter.register("RSA NetWitness ESA", "Splunk")
def netwitness_esa_to_splunk(rule_content, additional_fields, model=None):
    """Convert RSA NetWitness ESA rule to Splunk rule using IR as intermediate"""
    try:
        # Step 1: Generate IR from NetWitness ESA rule
        ir_result = generate_ir(rule_content, model, rule_type="RSA NetWitness ESA")

        # Step 2: Generate Splunk rule from IR
        splunk_rule = generate_rule_from_ir(ir_result, "Splunk", model)

        return splunk_rule
    except Exception as e:
        return f"Error converting NetWitness ESA to Splunk: {str(e)}"


# RSA NetWitness ESA → Microsoft Sentinel 转换（使用IR中间层）
@RuleConverter.register("RSA NetWitness ESA", "Microsoft Sentinel")
def netwitness_esa_to_sentinel(rule_content, additional_fields, model=None):
    """Convert RSA NetWitness ESA rule to Microsoft Sentinel rule using IR as intermediate"""
    try:
        # Step 1: Generate IR from NetWitness ESA rule
        ir_result = generate_ir(rule_content, model, rule_type="RSA NetWitness ESA")

        # Step 2: Generate Sentinel rule from IR
        sentinel_rule = generate_rule_from_ir(ir_result, "Microsoft Sentinel", model)

        return sentinel_rule
    except Exception as e:
        return f"Error converting NetWitness ESA to Sentinel: {str(e)}"


# RSA NetWitness ESA → Elastic 转换（使用IR中间层）
@RuleConverter.register("RSA NetWitness ESA", "Elastic")
def netwitness_esa_to_elastic(rule_content, additional_fields, model=None):
    """Convert RSA NetWitness ESA rule to Elastic rule using IR as intermediate"""
    try:
        # Step 1: Generate IR from NetWitness ESA rule
        ir_result = generate_ir(rule_content, model, rule_type="RSA NetWitness ESA")

        # Step 2: Generate Elastic rule from IR
        elastic_rule = generate_rule_from_ir(ir_result, "Elastic", model)

        return elastic_rule
    except Exception as e:
        return f"Error converting NetWitness ESA to Elastic: {str(e)}"


# RSA NetWitness ESA → Google Chronicle YARA-L 转换（使用IR中间层）
@RuleConverter.register("RSA NetWitness ESA", "Google Chronicle YARA-L")
def netwitness_esa_to_chronicle_yaral(rule_content, additional_fields, model=None):
    """Convert RSA NetWitness ESA rule to Google Chronicle YARA-L rule using IR as intermediate"""
    try:
        # Step 1: Generate IR from NetWitness ESA rule
        ir_result = generate_ir(rule_content, model, rule_type="RSA NetWitness ESA")

        # Step 2: Generate YARA-L rule from IR
        yaral_rule = generate_rule_from_ir(ir_result, "Google Chronicle YARA-L", model)

        return yaral_rule
    except Exception as e:
        return f"Error converting NetWitness ESA to YARA-L: {str(e)}"
