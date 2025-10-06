import logging
import re

from src.llms.client import client
from src.utils.helpers import safe_chat_completion


class RuleGenerator:
    @classmethod
    def web_rule_generator(
        cls,
        description: str,
        rule_type: str,
        required_fields: str = None,
        log_demo: str = None,
        model: str = None,
    ):
        dsl_rule_collected = ""
        for step, result in cls.generate_dsl_rule(
            description, rule_type, required_fields, log_demo, stream=True, model=model
        ):
            yield step, result
            if step == "FINAL_RESULT":
                dsl_rule_collected = result

        final_rule = cls.generate_rule_from_dsl(
            description, dsl_rule_collected, rule_type, model=model
        )
        yield "FINAL_RULE", final_rule

    @classmethod
    def generate_rule(
        cls,
        description: str,
        rule_type: str,
        required_fields: str = None,
        log_demo: str = None,
        model: str = None,
    ):
        logging.info("Generating DSL rule...")
        dsl_rule = cls.generate_dsl_rule(
            description, rule_type, required_fields, log_demo, stream=False, model=model
        )
        dsl_rule = next(dsl_rule)
        logging.info("Generating rule from DSL...")
        rule = cls.generate_rule_from_dsl(description, dsl_rule, rule_type, model=model)
        logging.info("Optimizing rule...")
        optimized_rule = cls.optimize_rule(rule, description, model=model)
        return optimized_rule

    @classmethod
    def generate_rule_simple(
        cls,
        description: str,
        rule_type: str,
        required_fields: str = None,
        log_demo: str = None,
        model: str = None,
    ) -> str:
        # analyse_result = cls._analyse_rule_description(description, rule_type)
        from src.llms.prompts import RULE_GENERATE_PROMPT_SIMPLE

        sys_prompt = RULE_GENERATE_PROMPT_SIMPLE.format(rule_type=rule_type)
        user_prompt = f"""
        The following is the {rule_type} rule description:
        {description}
        The following are the required fields:
        {required_fields}
        """
        messages = [
            {"role": "system", "content": sys_prompt},
            {"role": "user", "content": user_prompt},
        ]
        # try several times to get the response
        response = safe_chat_completion(messages, model=model)
        return response.choices[0].message.content

    @classmethod
    def optimize_rule(cls, rule: str, description: str, model: str = None) -> str:
        from src.llms.prompts import RULE_OPTIMIZE_PROMPT

        sys_prompt = RULE_OPTIMIZE_PROMPT
        user_prompt = f"""
        The following is the rule to be optimized:
        {rule}
        The following is the description of the rule:
        {description}
        """
        messages = [
            {"role": "system", "content": sys_prompt},
            {"role": "user", "content": user_prompt},
        ]
        response = safe_chat_completion(messages, model=model)
        rule_message = re.search(
            r"```spl\n(.*?)\n```", response.choices[0].message.content, re.DOTALL
        ).group(1)
        return rule_message

    @classmethod
    def _analyse_rule_description(
        cls, description: str, rule_type: str, model: str = None
    ):
        from src.llms.prompts import DESCRIPTION_ANALYSE_PROMPT

        system_prompt = DESCRIPTION_ANALYSE_PROMPT.format(rule_type=rule_type)
        user_prompt = f"""
                The following is a description of the {rule_type} rule:
                {description}
                """
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]
        analyse_response = client.chat.completions.create(
            messages=messages, model=model
        )
        analyse_result = analyse_response.choices[0].message.content
        return analyse_result

    @classmethod
    def generate_dsl_rule(
        cls,
        description: str,
        rule_type: str,
        required_fields: str = None,
        log_demo: str = None,
        stream: bool = False,
        model: str = None,
    ):
        from src.llms.prompts import TASK_BREAKDOWN_PROMPTS
        from src.llms.prompts import DSL_GENERATION_PROMPT
        from src.llms.data import DSL_KEYWORD

        keyword = "\n".join(f"{k}: {v}" for k, v in DSL_KEYWORD.items())
        sys_prompt = DSL_GENERATION_PROMPT.format(
            rule_type=rule_type, rule_description=description, keyword=keyword
        )
        # if it has required fields, add to the prompt
        if required_fields:
            sys_prompt += f"\nBelow are the required fields:\n{required_fields}"
        if log_demo:
            sys_prompt += f"\nBelow is a demo log:\n{log_demo}"
        dsl_msgs = [{"role": "system", "content": sys_prompt}]
        breakdown_msgs = []
        background_prompt = TASK_BREAKDOWN_PROMPTS["BACKGROUND"].format(
            rule_type=rule_type, description=description
        )
        breakdown_msgs.append({"role": "system", "content": background_prompt})

        dsl_rules = []
        steps = [
            "UNDERSTANDING_PROBLEM",
            "IDENTIFY_DATA_SOURCE",
            "DEFINE_INITIAL_FILTERS",
            "EXTRACT_RELEVANT_FIELDS",
            "PERFORM_DATA_AGGREGATION",
            "CALCULATE_DERIVED_METRICS",
            "FILTER_ANOMALIES",
            "OPTIMIZE_OUTPUT",
        ]

        for step in steps:
            _, step_output = cls._analyse_subtask(
                breakdown_msgs, dsl_msgs, step, model=model
            )
            dsl_rules.extend(step_output)

            if stream:
                yield step, _
                yield step, step_output

        print(dsl_rules)
        # optimize the dsl rules
        dsl_rules_str_optimized = cls._optimize_dsl_rule(
            dsl_rules, description, model=model
        )
        print(dsl_rules_str_optimized)
        if stream:
            yield "FINAL_RESULT", dsl_rules_str_optimized
        else:
            yield dsl_rules_str_optimized

    @classmethod
    def _analyse_subtask(
        cls, breakdown_msgs: list, dsl_msgs: list, subtask_name: str, model: str = None
    ) -> tuple:
        from src.llms.prompts import TASK_BREAKDOWN_PROMPTS

        subtask_prompt = TASK_BREAKDOWN_PROMPTS[subtask_name]
        breakdown_msgs.append({"role": "user", "content": subtask_prompt})
        try:
            response = client.chat.completions.create(
                messages=breakdown_msgs, model=model
            )
        except Exception as e:
            logging.error(f"Error: {e}")
            return "", ""
        analyse_message = response.choices[0].message.content
        breakdown_msgs.append({"role": "assistant", "content": analyse_message})

        dsl_msgs.append(
            {
                "role": "user",
                "content": subtask_name.replace("_", " ") + ":\n" + analyse_message,
            }
        )
        try:
            response = client.chat.completions.create(messages=dsl_msgs, model=model)
        except Exception as e:
            logging.error(f"Error: {e}")
            return "", ""
        dsl_message = response.choices[0].message.content
        dsl_msgs.append({"role": "assistant", "content": dsl_message})
        # use re to extract the text between ```plaintext and ```
        dsl_message = re.search(
            r"```plaintext\n(.*?)\n```", dsl_message, re.DOTALL
        ).group(1)
        # split the dsl message by \n and remove the empty lines
        dsl_rules = [line for line in dsl_message.split("\n") if line.strip()]
        print(subtask_name.replace("_", " ") + ":\n" + analyse_message)
        print(dsl_rules)
        return analyse_message, dsl_rules

    @classmethod
    def _optimize_dsl_rule(cls, dsl_rules, rule_description, model: str = None) -> str:
        from src.llms.prompts import DSL_OPTIMIZE_PROMPT
        from src.llms.data import DSL_KEYWORD

        dsl_rules_str = "\n".join(dsl_rules)
        sys_prompt = DSL_OPTIMIZE_PROMPT.format(
            keyword="\n".join(f"{k}: {v}" for k, v in DSL_KEYWORD.items())
        )
        user_prompt = f"## DSL Rules:\n{dsl_rules_str}\n\n## Rule Description:\n{rule_description}"
        messages = [
            {"role": "system", "content": sys_prompt},
            {"role": "user", "content": user_prompt},
        ]
        try:
            response = client.chat.completions.create(messages=messages, model=model)
        except Exception as e:
            logging.error(f"Error: {e}")
            return ""
        response_message = response.choices[0].message.content
        dsl_message = re.search(
            r"```plaintext\n(.*?)\n```", response_message, re.DOTALL
        ).group(1)
        return dsl_message

    @classmethod
    def generate_rule_from_dsl(
        cls,
        description: str,
        dsl_rule: str,
        rule_type: str,
        required_fields: list = None,
        model: str = None,
    ) -> str:
        from src.llms.prompts import RULE_GENERATE_FROM_DSL_PROMPT
        from src.llms.data import DSL_KEYWORD

        sys_prompt = RULE_GENERATE_FROM_DSL_PROMPT.format(
            rule_type=rule_type,
            keyword="\n".join(f"{k}: {v}" for k, v in DSL_KEYWORD.items()),
        )
        if required_fields:
            sys_prompt += f"\n## Below are the required fields:\n{required_fields}"
        user_prompt = (
            f"## DSL Rule:\n{dsl_rule} \n\n ## Rule Description:\n{description}"
        )
        messages = [
            {"role": "system", "content": sys_prompt},
            {"role": "user", "content": user_prompt},
        ]
        response = safe_chat_completion(messages, model=model)
        return response.choices[0].message.content
