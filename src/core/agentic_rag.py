"""
Agentic RAG module for intelligent rule optimization using vector database.
"""

import logging
import json
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path


# Vector database imports
import chromadb
from chromadb.config import Settings

from src.schemas.models import OptimizationTask, OptimizationResult
from src.llms.client import client
from src.core.prompts import (
    get_agentic_rag_system_prompt,
    build_rag_search_prompt,
    build_rule_optimization_prompt,
)
from src.utils.conversion_logger import conversion_logger


class VectorDatabaseBuilder:
    """Loads and manages existing vector databases for each SIEM."""

    def __init__(self, base_db_path: str = "./vector_db"):
        self.base_db_path = Path(base_db_path)
        self.siem_databases = {}  # Store database instances for each SIEM

        # Auto-discover and load existing SIEM databases
        self._discover_existing_databases()

    def _discover_existing_databases(self):
        """Discover and load existing SIEM databases."""
        if not self.base_db_path.exists():
            return

        # Look for SIEM directories
        siem_dirs = [
            "Splunk",
            "Microsoft Sentinel",
            "IBM QRadar",
            "Google Chronicle",
            "RSA NetWitness",
        ]

        for siem in siem_dirs:
            siem_db_path = self.base_db_path / siem
            if siem_db_path.exists():
                try:
                    # Try to load existing database
                    client = chromadb.PersistentClient(
                        path=str(siem_db_path),
                        settings=Settings(anonymized_telemetry=False, allow_reset=True),
                    )

                    # Try to get existing collection
                    collection_name = (
                        f"siem_{siem.lower().replace(' ', '_').replace('-', '_')}"
                    )
                    try:
                        collection = client.get_collection(name=collection_name)

                        # Store database info
                        self.siem_databases[siem] = {
                            "client": client,
                            "collection": collection,
                            "path": siem_db_path,
                            "collection_name": collection_name,
                        }

                        logging.info(
                            f"Loaded existing database for {siem} from {siem_db_path}"
                        )

                    except Exception as e:
                        logging.warning(
                            f"Collection {collection_name} not found for {siem}: {str(e)}"
                        )
                        # Collection doesn't exist, but we'll create it when needed

                except Exception as e:
                    logging.warning(
                        f"Failed to load existing database for {siem}: {str(e)}"
                    )

    def search(
        self, query: str, siem_name: str = None, n_results: int = 5
    ) -> Dict[str, Any]:
        """Search the vector database."""
        try:
            if siem_name:
                # Search in specific SIEM database
                if siem_name not in self.siem_databases:
                    logging.warning(f"Database for {siem_name} not found")
                    return {}

                db_info = self.siem_databases[siem_name]
                collection = db_info["collection"]
                results = collection.query(query_texts=[query], n_results=n_results)
            else:
                # Search across all databases
                all_results = []
                for siem, db_info in self.siem_databases.items():
                    try:
                        collection = db_info["collection"]
                        results = collection.query(
                            query_texts=[query], n_results=n_results
                        )
                        # Add SIEM information to results
                        if results and results.get("documents"):
                            for i, doc in enumerate(results["documents"][0]):
                                if results.get("metadatas") and results["metadatas"][0]:
                                    results["metadatas"][0][i]["siem"] = siem
                        all_results.append(results)
                    except Exception as e:
                        logging.warning(f"Search failed for {siem}: {str(e)}")
                        continue

                # Combine results (simplified approach)
                if all_results:
                    results = all_results[0]  # Return first successful result for now
                else:
                    results = {}

            return results

        except Exception as e:
            logging.error(f"Search failed: {str(e)}")
            return {}

    def get_database_info(self) -> Dict[str, Any]:
        """Get information about all databases."""
        try:
            info = {
                "total_databases": len(self.siem_databases),
                "databases": {},
                "base_path": "vector_db",  # Use relative path from project root
            }

            for siem_name, db_info in self.siem_databases.items():
                try:
                    collection = db_info["collection"]
                    count = collection.count()

                    # Convert absolute path to relative path from project root
                    absolute_path = Path(db_info["path"])
                    project_root = Path(__file__).parent.parent.parent
                    relative_path = absolute_path.relative_to(project_root)

                    info["databases"][siem_name] = {
                        "collection_name": db_info["collection_name"],
                        "database_path": str(relative_path),  # Store relative path
                        "total_chunks": count,
                        "metadata": collection.metadata,
                    }
                except Exception as e:
                    logging.warning(
                        f"Failed to get info for {siem_name} database: {str(e)}"
                    )
                    info["databases"][siem_name] = {"error": str(e)}

            return info

        except Exception as e:
            logging.error(f"Failed to get database info: {str(e)}")
            return {"error": str(e)}


class AgenticRAGOptimizer:
    """Agentic RAG system for intelligent rule optimization."""

    def __init__(self, vector_db_path: str = "vector_db", model: str = "gpt-4o-mini"):
        """
        Initialize the Agentic RAG Optimizer.

        Args:
            vector_db_path: Path to the vector database
            model: OpenAI model to use for optimization
        """
        self.vector_db_path = vector_db_path
        self.model = model
        self.client = client
        self.logger = logging.getLogger(__name__)

        # Initialize vector database
        try:
            self.vector_db = VectorDatabaseBuilder(vector_db_path)
            self.logger.info(f"Vector database initialized from {vector_db_path}")
        except Exception as e:
            self.logger.error(f"Failed to initialize vector database: {e}")
            self.vector_db = None

        if not self.client:
            self.logger.warning(
                "OpenAI client not available. Please check your API key."
            )

    def complete_optimization_task(
        self, task: OptimizationTask, original_rule: str, rule_type: str
    ) -> Optional[OptimizationResult]:
        """
        Complete a single optimization task using Agentic RAG.

        Args:
            task: The optimization task to complete
            original_rule: The original rule content
            rule_type: Type of the rule (SIEM type)

        Returns:
            OptimizationResult or None if completion fails
        """
        if not self.client or not self.vector_db:
            self.logger.error("Required components not available")
            return None

        try:
            # Step 1: Intelligent RAG search with reflection and adjustment
            search_results = self._intelligent_rag_search(task, rule_type)

            # Step 2: Rule optimization based on retrieved context
            optimized_rule = self._optimize_rule_with_context(
                task, original_rule, search_results, rule_type
            )

            # Step 3: Evaluate semantic preservation
            semantic_score = self._evaluate_semantic_preservation(
                original_rule, optimized_rule
            )

            # Step 4: Create optimization result
            result = OptimizationResult(
                task_name=task.task_name,
                original_rule=original_rule,
                optimized_rule=optimized_rule,
                search_keyword_used=task.search_keyword,
                retrieved_context=search_results,
                optimization_explanation=self._generate_optimization_explanation(
                    task, search_results, optimized_rule
                ),
                semantic_preservation_score=semantic_score,
            )

            # Log optimization results
            conversion_logger.log_optimization_results([result])

            self.logger.info(f"Completed optimization task: {task.task_name}")
            return result

        except Exception as e:
            self.logger.error(
                f"Failed to complete optimization task {task.task_name}: {e}"
            )
            return None

    def _intelligent_rag_search(
        self, task: OptimizationTask, rule_type: str, max_iterations: int = 3
    ) -> List[str]:
        """
        Perform intelligent RAG search with reflection and keyword adjustment.

        Args:
            task: The optimization task
            rule_type: Type of the rule
            max_iterations: Maximum number of search iterations

        Returns:
            List of retrieved context strings
        """
        current_keyword = task.search_keyword
        all_results = []

        for iteration in range(max_iterations):
            self.logger.info(
                f"RAG search iteration {iteration + 1} with keyword: {current_keyword}"
            )

            # Search vector database
            search_query = current_keyword
            results = self.vector_db.search(
                search_query, siem_name=rule_type, n_results=5
            )

            if not results or not results.get("documents"):
                self.logger.warning(f"No results found in iteration {iteration + 1}")
                break

            # Extract and store results
            documents = results.get("documents", [])
            retrieved_docs = []
            for doc in documents:
                if isinstance(doc, list) and len(doc) > 0:
                    doc_content = doc[0]
                    all_results.append(doc_content)
                    retrieved_docs.append(doc_content)
                elif isinstance(doc, str):
                    all_results.append(doc)
                    retrieved_docs.append(doc)

            # Log RAG search step
            conversion_logger.log_rag_search_step(
                iteration=iteration + 1,
                task_name=task.task_name,
                search_keyword=current_keyword,
                search_query=search_query,
                retrieved_documents=retrieved_docs,
                metadata={
                    "siem_name": rule_type,
                    "n_results": 5,
                    "results_found": len(retrieved_docs),
                },
            )

            # Reflect on search results and adjust keyword if needed
            if iteration < max_iterations - 1:
                adjusted_keyword = self._reflect_and_adjust_keyword(
                    task, current_keyword, all_results, rule_type
                )

                if adjusted_keyword == current_keyword:
                    self.logger.info("Keyword converged, stopping search iterations")
                    break

                current_keyword = adjusted_keyword

        return all_results[:10]  # Return top 10 results

    def _reflect_and_adjust_keyword(
        self,
        task: OptimizationTask,
        current_keyword: str,
        current_results: List[str],
        rule_type: str,
    ) -> str:
        """
        Reflect on search results and adjust keyword for better retrieval.

        Args:
            task: The optimization task
            current_keyword: Current search keyword
            current_results: Current search results
            rule_type: Type of the rule

        Returns:
            Adjusted keyword
        """
        try:
            # Create reflection prompt
            reflection_prompt = f"""
            Task: {task.task_name}
            Description: {task.description}
            Current Keyword: {current_keyword}
            Current Results: {current_results[:3]}  # Show first 3 results
            
            🔒 CRITICAL: This search is for SYNTAX-ONLY optimizations. The goal is to find documentation that helps improve:
            - Code structure and formatting
            - Keyword usage and syntax best practices  
            - Performance optimization techniques
            - Platform-specific syntax improvements
            
            ⚠️  NEVER search for content that would change detection logic, field values, or threat detection criteria!
            
            Based on the current search results, analyze if the keyword is effective:
            1. Are the results relevant to SYNTAX optimization (not semantic changes)?
            2. What keyword might better find syntax/structure improvement documentation?
            3. Should the current keyword be modified to focus on syntax best practices?
            
            Return only a single optimized keyword focused on syntax/structure improvements, no other text.
            
            Example: 
            ```json
            "optimized_keyword"
            ```
            """

            # Get keyword adjustment from LLM
            response = self._call_openai_api(reflection_prompt, max_tokens=500)

            if response:
                try:
                    # 尝试直接解析JSON
                    adjusted_keyword = json.loads(response)
                    if isinstance(adjusted_keyword, str):
                        self.logger.info(
                            f"Keyword adjusted from {current_keyword} to {adjusted_keyword}"
                        )
                        # Log keyword adjustment step
                        conversion_logger.log_keyword_adjustment_step(
                            iteration=0,  # Will be updated by caller
                            task_name=task.task_name,
                            original_keyword=current_keyword,
                            adjusted_keyword=adjusted_keyword,
                            reflection_prompt=reflection_prompt,
                            reflection_response=response,
                            metadata={"adjustment_method": "direct_json"},
                        )
                        return adjusted_keyword
                except json.JSONDecodeError:
                    # 如果直接解析失败，尝试提取```json代码块
                    try:
                        import re

                        # 查找```json...```代码块
                        json_match = re.search(r"```json\s*([\s\S]*?)\s*```", response)
                        if json_match:
                            json_content = json_match.group(1).strip()
                            adjusted_keyword = json.loads(json_content)
                            if isinstance(adjusted_keyword, str):
                                self.logger.info(
                                    f"Keyword adjusted from {current_keyword} to {adjusted_keyword} (extracted from code block)"
                                )
                                # Log keyword adjustment step
                                conversion_logger.log_keyword_adjustment_step(
                                    iteration=0,  # Will be updated by caller
                                    task_name=task.task_name,
                                    original_keyword=current_keyword,
                                    adjusted_keyword=adjusted_keyword,
                                    reflection_prompt=reflection_prompt,
                                    reflection_response=response,
                                    metadata={"adjustment_method": "json_code_block"},
                                )
                                return adjusted_keyword
                    except (json.JSONDecodeError, AttributeError) as e:
                        self.logger.warning(
                            f"Failed to parse keyword adjustment response from code block: {e}"
                        )
                        self.logger.debug(f"Raw response: {response}")

                self.logger.warning(
                    f"Failed to parse keyword adjustment response: {response}"
                )

            # Fallback: return current keyword
            return current_keyword

        except Exception as e:
            self.logger.warning(f"Failed to adjust keyword: {e}")
            return current_keyword

    def _optimize_rule_with_context(
        self,
        task: OptimizationTask,
        original_rule: str,
        context: List[str],
        rule_type: str,
    ) -> str:
        """
        Optimize the rule based on retrieved context while preserving semantics.

        Args:
            task: The optimization task
            original_rule: The original rule content
            context: Retrieved context from RAG search
            rule_type: Type of the rule

        Returns:
            Optimized rule content
        """
        try:
            # Create optimization prompt
            optimization_prompt = build_rule_optimization_prompt(
                task.to_str(), original_rule, context, rule_type
            )

            # Get optimization from LLM
            response = self._call_openai_api(optimization_prompt, max_tokens=2000)

            if response:
                # Extract the optimized rule from response
                optimized_rule = self._extract_optimized_rule(response)
                if optimized_rule:
                    # Log rule optimization step
                    conversion_logger.log_rule_optimization_step(
                        task_name=task.task_name,
                        original_rule=original_rule,
                        optimized_rule=optimized_rule,
                        optimization_prompt=optimization_prompt,
                        optimization_response=response,
                        semantic_score=0.0,  # Will be updated later
                        metadata={
                            "rule_type": rule_type,
                            "context_count": len(context),
                        },
                    )
                    return optimized_rule

            # Fallback: return original rule
            self.logger.warning("Failed to optimize rule, returning original")
            return original_rule

        except Exception as e:
            self.logger.error(f"Failed to optimize rule: {e}")
            return original_rule

    def _evaluate_semantic_preservation(
        self, original_rule: str, optimized_rule: str
    ) -> float:
        """
        Evaluate how well the optimized rule preserves the semantic meaning.

        Args:
            original_rule: The original rule content
            optimized_rule: The optimized rule content

        Returns:
            Semantic preservation score (0-1)
        """
        try:
            evaluation_prompt = f"""
            Original Rule:
            {original_rule}
            
            Optimized Rule:
            {optimized_rule}
            
            🔒 CRITICAL SEMANTIC PRESERVATION EVALUATION:
            You must evaluate if the optimized rule maintains IDENTICAL semantic meaning to the original.
            
            STRICT EVALUATION CRITERIA:
            1. ✅ Does it detect EXACTLY the same threats/events? (No more, no less)
            2. ✅ Are ALL logical conditions and operators identical in effect?
            3. ✅ Are ALL field names, values, and patterns preserved?
            4. ✅ Are ALL thresholds, timeframes, and numeric criteria unchanged?
            5. ✅ Would both rules trigger on the EXACT same log entries?
            
            ❌ SEMANTIC VIOLATIONS (score should be 0.0 if ANY exist):
            - Any detection logic changes
            - Any added or removed threat detection criteria
            - Any modified field values or patterns
            - Any altered logical operators that change scope
            - Any changed thresholds or numeric values
            
            ⚠️  SCORING GUIDE:
            - 1.0: Perfect semantic preservation (ONLY syntax/structure changes)
            - 0.8-0.9: Minor syntax differences but identical detection
            - 0.5-0.7: Some semantic differences detected
            - 0.0-0.4: Significant semantic changes (UNACCEPTABLE)
            
            Return only a JSON object with a "score" field (0-1), where 1 means perfect semantic preservation.

            Example:
            {{"score": 0.9}}
            """

            response = self._call_openai_api(evaluation_prompt, max_tokens=100)

            if response:
                try:
                    # First try to parse JSON directly
                    result = json.loads(response)
                    score = result.get("score", 0.5)
                    return min(max(float(score), 0.0), 1.0)  # Clamp between 0 and 1
                except (json.JSONDecodeError, ValueError):
                    # If direct parsing fails, try to extract JSON from code blocks
                    try:
                        import re

                        # Look for ```json...``` code blocks
                        json_match = re.search(r"```json\s*([\s\S]*?)\s*```", response)
                        if json_match:
                            json_content = json_match.group(1).strip()
                            result = json.loads(json_content)
                            score = result.get("score", 0.5)
                            self.logger.info(
                                f"Extracted score {score} from JSON code block"
                            )
                            return min(max(float(score), 0.0), 1.0)
                    except (json.JSONDecodeError, AttributeError) as e:
                        self.logger.debug(f"Failed to parse JSON from code block: {e}")
                        pass

                    self.logger.warning(
                        f"Failed to evaluate semantic preservation: {response}"
                    )

            # Fallback: return moderate score
            return 0.5

        except Exception as e:
            self.logger.warning(f"Failed to evaluate semantic preservation: {e}")
            return 0.5

    def _generate_optimization_explanation(
        self, task: OptimizationTask, context: List[str], optimized_rule: str
    ) -> str:
        """Generate explanation of what was optimized and why."""
        try:
            explanation_prompt = f"""
            Task: {task.task_name}
            Description: {task.description}
            Context Retrieved: {len(context)} relevant documents
            Optimization Applied: Rule has been optimized based on best practices
            
            🔒 IMPORTANT: This was a SYNTAX-ONLY optimization that preserved semantic meaning.
            
            Provide a brief explanation of what SYNTAX/STRUCTURE changes were made and why, based on the retrieved context.
            Emphasize that:
            1. NO detection logic was changed
            2. Only syntax, structure, and performance were improved
            3. The rule detects EXACTLY the same threats as before
            
            Keep it concise and technical.
            """

            response = self._call_openai_api(explanation_prompt, max_tokens=300)
            return (
                response
                if response
                else "Rule optimized based on retrieved context and best practices."
            )

        except Exception as e:
            self.logger.warning(f"Failed to generate explanation: {e}")
            return "Rule optimized based on retrieved context and best practices."

    def _extract_optimized_rule(self, response: str) -> Optional[str]:
        """Extract the optimized rule from the LLM response."""
        try:
            # Extract content from ``` code blocks by removing lines with "```"
            lines = response.split("\n")
            rule_lines = []
            in_code_block = False

            for line in lines:
                # Skip lines that contain "```"
                if "```" in line:
                    in_code_block = not in_code_block  # Toggle code block state
                    continue

                # If we're in a code block, collect the content
                if in_code_block:
                    rule_lines.append(line)

            if rule_lines:
                rule_content = "\n".join(rule_lines).strip()
                self.logger.info(
                    f"Extracted rule from code block: {len(rule_lines)} lines"
                )
                return rule_content

            self.logger.warning(f"No rule content found in response: {response}")
            return None

        except Exception as e:
            self.logger.warning(
                f"Failed to extract optimized rule: {e}, response: {response}"
            )
            return None

    def _call_openai_api(self, prompt: str, max_tokens: int = 1000) -> Optional[str]:
        """Call OpenAI API with compatibility for both old and new versions."""
        try:
            # Try new version API first
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": get_agentic_rag_system_prompt()},
                    {"role": "user", "content": prompt},
                ],
                max_tokens=max_tokens,
            )
            return response.choices[0].message.content

        except AttributeError:
            # Fall back to old version API
            try:
                response = self.client.ChatCompletion.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": get_agentic_rag_system_prompt()},
                        {"role": "user", "content": prompt},
                    ],
                    max_tokens=max_tokens,
                )
                return response.choices[0].message.content

            except Exception as e:
                self.logger.error(
                    f"Failed to call OpenAI API with old version: {str(e)}"
                )
                return None

        except Exception as e:
            self.logger.error(f"Failed to call OpenAI API: {str(e)}")
            return None
