"""MITRE ATLAS reference for the techniques Jinx uses.

Generated from the official ATLAS data (github.com/mitre-atlas/atlas-data,
dist/v6/ATLAS-2026.10.yaml). Regenerate on a new ATLAS release; do not hand-edit names.
"""

ATLAS_VERSION = "2026.10"

# technique id -> (name, [tactics])
ATLAS = {
    'AML.T0050': ('Command and Scripting Interpreter', ['Execution']),
    'AML.T0051': ('LLM Prompt Injection', ['Execution']),
    'AML.T0051.000': ('LLM Prompt Injection: Direct', ['Execution']),
    'AML.T0051.001': ('LLM Prompt Injection: Indirect', ['Execution']),
    'AML.T0051.002': ('LLM Prompt Injection: Triggered', ['Execution']),
    'AML.T0052': ('Phishing', ['Initial Access', 'Lateral Movement']),
    'AML.T0053': ('AI Agent Tool Invocation', ['Execution', 'Privilege Escalation', 'Lateral Movement']),
    'AML.T0054': ('LLM Jailbreak', ['Defense Evasion', 'Privilege Escalation']),
    'AML.T0055': ('Unsecured Credentials', ['Credential Access']),
    'AML.T0060': ('Publish Hallucinated Entities', ['Resource Development']),
    'AML.T0062': ('Discover LLM Hallucinations', ['Discovery']),
    'AML.T0066': ('Retrieval Content Crafting', ['AI Attack Adaptation']),
    'AML.T0068': ('LLM Prompt Obfuscation', ['Defense Evasion']),
    'AML.T0069.002': ('Discover LLM System Information: System Prompt', ['Discovery']),
    'AML.T0077': ('LLM Response Rendering', ['Exfiltration']),
    'AML.T0080': ('AI Agent Context Poisoning', ['Persistence']),
    'AML.T0081': ('Modify AI Agent Configuration', ['Persistence', 'Defense Evasion']),
    'AML.T0084': ('Discover AI Agent Configuration', ['Discovery']),
    'AML.T0084.001': ('Discover AI Agent Configuration: Tool Definitions', ['Discovery']),
    'AML.T0085.000': ('Data from AI Services: RAG Databases', ['Collection']),
    'AML.T0085.002': ('Data from AI Services: Conversation Context and Memory', ['Collection']),
    'AML.T0086': ('Exfiltration via AI Agent Tool Invocation', ['Exfiltration']),
    'AML.T0092': ('Manipulate User LLM Chat History', ['Defense Evasion']),
    'AML.T0093': ('Prompt Infiltration via Public-Facing Application', ['Initial Access', 'Persistence']),
    'AML.T0097': ('Virtualization/Sandbox Evasion', ['Defense Evasion']),
    'AML.T0098': ('AI Agent Tool Credential Harvesting', ['Credential Access']),
    'AML.T0099': ('AI Agent Tool Data Poisoning', ['Persistence']),
    'AML.T0101': ('Data Destruction via AI Agent Tool Invocation', ['Impact']),
    'AML.T0105': ('Escape to Host', ['Privilege Escalation']),
    'AML.T0110': ('AI Agent Tool Poisoning', ['Persistence']),
    'AML.T0130': ('AI Agent Response Biasing', ['Impact']),
    'AML.T0133': ('Discover AI Agent Runtime Capabilities', ['Discovery']),
    'AML.T0136': ('Exfiltration via AI User Interface', ['Exfiltration']),
    'AML.T0137.003': ('Training Data Information from AI Models: Extract Memorized Data', ['Collection']),
}


def label(ids):
    """Human label for a list of ATLAS ids; empty list -> "no ATLAS match"."""
    if not ids:
        return "no ATLAS match"
    return "; ".join(f"{i} {ATLAS[i][0]}" if i in ATLAS else i for i in ids)
