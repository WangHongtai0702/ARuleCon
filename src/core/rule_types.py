from abc import ABC, abstractmethod


class Rule(ABC):
    def __init__(self, rule_type: str, rule_content: str):
        self.rule_type = rule_type
        self.rule_content = rule_content

    @abstractmethod
    def preprocess(self):
        """Preprocess the rule content, e.g., split pipes, extract fields, etc."""
        pass

    @classmethod
    @abstractmethod
    def from_convert_result(cls, *args, **kwargs):
        """Construct a rule from conversion result (e.g., list of pipes)."""
        pass

    def __str__(self):
        return f"Rule Type: {self.rule_type}\nRule Content: {self.rule_content}"


class SplunkRule(Rule):
    def __init__(self, rule_content: str):
        super().__init__('Splunk', rule_content)
        self.pipes = []
        self.preprocess()

    def preprocess(self):
        # 这里只做简单分割，具体pipe解析逻辑应在别的工具/模块实现
        self.pipes = [pipe.strip() for pipe in self.rule_content.split("|") if pipe.strip()]

    @classmethod
    def from_convert_result(cls, pipes: list) -> 'SplunkRule':
        rule_content = " | ".join(pipes)
        return cls(rule_content=rule_content)


class SentinelRule(Rule):
    def __init__(self, rule_content: str):
        super().__init__('Microsoft Sentinel', rule_content)
        self.pipes = []
        self.preprocess()

    def preprocess(self):
        self.pipes = [pipe.strip() for pipe in self.rule_content.split("|") if pipe.strip()]

    @classmethod
    def from_convert_result(cls, pipes: list) -> 'SentinelRule':
        rule_content = " | ".join(pipes)
        return cls(rule_content=rule_content)


class GoogleChronicleYARALRule(Rule):
    def __init__(self, rule_content: str):
        super().__init__('Google Chronicle YARA-L', rule_content)
        self.pipes = []
        self.preprocess()

    def preprocess(self):
        # Chronicle YARA-L 规则的分割方式可根据实际格式调整
        self.pipes = [pipe.strip() for pipe in self.rule_content.split('|') if pipe.strip()]

    @classmethod
    def from_convert_result(cls, pipes: list) -> 'GoogleChronicleYARALRule':
        rule_content = ' | '.join(pipes)
        return cls(rule_content=rule_content)
