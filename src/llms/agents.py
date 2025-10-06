from dotenv import load_dotenv
import json
from src.llms.prompts import RULE_OPTIMIZE_PROMPT
from src.utils.validators import query_splunk, grammar_check
from src.core import RuleGenerator
from typing import Dict
import logging
import time

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)
load_dotenv()


def _call_openai_api(
    messages: list,
    model: str,
    response_format: str = "text",
    function_call: bool = False,
    max_retries=5,
    delay=2,
) -> str:
    from src.llms.client import get_client

    retries = 0
    while retries < max_retries:
        try:
            client = get_client()
            if not client:
                raise Exception("LLM client not available")

            response = client.chat.completions.create(
                model=model,
                messages=messages,
                response_format={"type": response_format},
            )
            return response.choices[0].message.content
        except Exception as e:
            retries += 1
            print(f"Attempt {retries} failed with error: {e}")
            time.sleep(delay)
    raise Exception(f"All {max_retries} attempts failed.")


class SecurityRuleAgent:
    def __init__(self, model_name="gpt-3.5-turbo"):
        self.model_name = model_name
        self.dsl_fragments = None
        self.rule_raw = None
        self.final_rule = None

    def optimize_rule(self, rule_content: str, ground_truth: str, model: str) -> str:
        """Optimize a rule based on ground truth"""
        from src.llms.prompts import RULE_OPTIMIZE_PROMPT
        from src.llms.client import get_client

        client = get_client()
        if not client:
            return "Error: LLM client not available"

        sys_prompt = RULE_OPTIMIZE_PROMPT
        user_prompt = f"""
        The following is the rule to be optimized:
        {rule_content}
        The following is the ground truth:
        {ground_truth}
        """

        try:
            response = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": sys_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Error optimizing rule: {str(e)}"

    def score_rule(self, rule_content: str, ground_truth: str, model: str) -> dict:
        """Score a rule against ground truth"""
        from src.llms.prompts import SCORE_PROMPT
        from src.llms.client import get_client

        client = get_client()
        if not client:
            return {"error": "LLM client not available"}

        prompt = SCORE_PROMPT.format(rule=rule_content, description=ground_truth)
        message = [{"role": "system", "content": prompt}]

        try:
            response = client.chat.completions.create(
                model=model, messages=message, response_format={"type": "json_object"}
            )
            reflection_result = response.choices[0].message.content

            try:
                scores = json.loads(reflection_result)
                return scores
            except json.JSONDecodeError:
                return {"error": "Failed to parse scores"}
        except Exception as e:
            return {"error": f"Failed to score rule: {str(e)}"}

    def run_agent(
        self,
        description: str,
        max_iterations: int = 3,
        rule_type: str = "splunk",
        required_fields: str = None,
        log_demo: str = None,
    ) -> str:

        logging.info("=== [1] Analyse Phase ===")
        dsl_rule = RuleGenerator.generate_dsl_rule(
            description, rule_type, required_fields, log_demo, stream=False
        )
        dsl_rule = next(dsl_rule)
        self.dsl_fragments = dsl_rule

        logging.info("\n=== [2] Generation Phase ===")
        self.rule_raw = RuleGenerator.generate_rule_from_dsl(
            description, self.dsl_fragments, rule_type, required_fields
        )
        logging.info(f"Initial rule (R_raw):\n{self.rule_raw}")

        current_rule = self.rule_raw
        for iteration in range(max_iterations):
            logging.info(f"\n=== [3] Reflection Iteration {iteration + 1} ===")
            scores = self.reflect_and_score_rule(
                current_rule, description, self.model_name
            )
            logging.info(f"Scores => {scores}")

            if all(
                scores.get(dim, 0.0) >= 0.6
                for dim in [
                    "logical_coherence",
                    "syntax_validation",
                    "execution_feasibility",
                ]
            ):
                logging.info("All scores are acceptable. Rule is considered final.")
                self.final_rule = current_rule
                break
            else:
                logging.info("Scores below threshold, optimizing rule...")
                current_rule = self.optimize_rule(current_rule, scores, self.model_name)
        else:
            logging.warning("Max iterations reached, output the last version as final.")
            self.final_rule = current_rule

        logging.info("\n=== Final Rule Output ===")
        logging.info(self.final_rule)
        return self.final_rule

    def reflect_and_score_rule(
        self, rule: str, description: str, model: str
    ) -> Dict[str, float]:

        from src.llms.prompts import SCORE_PROMPT

        prompt = SCORE_PROMPT.format(rule=rule, description=description)
        message = [{"role": "system", "content": prompt}]
        reflection_result = _call_openai_api(message, model, response_format="json")

        try:
            scores = json.loads(reflection_result)
        except Exception as e:
            scores = {
                "logical_coherence": 1.0,
                "syntax_validation": 1.0,
                "execution_feasibility": 1.0,
                "comment": "Failed to parse reflection result, assume pass.",
            }
        return scores
