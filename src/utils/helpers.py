import time

from dotenv import load_dotenv
import openai
import os
import json
import yaml
from pathlib import Path
from src.llms.prompts import PREPROCESSING_PROMPT

load_dotenv()
PROJECT_ROOT = Path(__file__).resolve().parent.parent


def extract_info_from_markdown_table(markdown_table: str, model: str) -> dict:
    """Extract information from markdown table using LLM"""
    from src.llms.client import get_client

    client = get_client()
    if not client:
        return {"error": "LLM client not available"}

    sys_prompt = PREPROCESSING_PROMPT
    user_prompt = f"""
    The following is a markdown table:
    {markdown_table}
    """

    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": sys_prompt},
                {"role": "user", "content": user_prompt},
            ],
            response_format={"type": "json_object"},
        )
        return json.loads(response.choices[0].message.content)
    except Exception as e:
        return {"error": f"Failed to process table: {str(e)}"}


def description_and_rule_generator(rule_type: str) -> dict:
    dataset_path = os.path.join(PROJECT_ROOT, f"dataset/descriptions/{rule_type}")
    for file in os.listdir(dataset_path):
        # read yaml file
        path = os.path.join(dataset_path, file)
        with open(path, "r") as f:
            data = f.read()
        # parse yaml file
        data = yaml.load(data, Loader=yaml.FullLoader)
        yield path, data


def optimize_rule(rule_content: str, ground_truth: str, model: str) -> str:
    """Optimize a rule based on ground truth"""
    from src.llms.prompts import OPTIMIZE_RULE_PROMPT
    from src.llms.client import get_client

    client = get_client()
    if not client:
        return "Error: LLM client not available"

    sys_prompt = OPTIMIZE_RULE_PROMPT
    user_prompt = f"""
    The following is the rule to optimize:
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


def load_conversion_dataset(file_path: str) -> dict:
    with open(file_path, "r") as f:
        data = f.read()
    return json.loads(data)


def safe_chat_completion(messages, model, max_retries=5, delay=2):
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
            )
            return response
        except Exception as e:
            retries += 1
            print(f"Attempt {retries} failed with error: {e}")
            time.sleep(delay)
    raise Exception(f"All {max_retries} attempts failed.")
