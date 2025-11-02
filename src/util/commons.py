from intentmodel.intent_model import AgentComponents
from clientshim.secure_model import AgentSpec
from intentmodel.intent_model import Tool
from agent.graph import ReActAgent
from typing import Dict
import hashlib, json, inspect, ast, textwrap

_TOOLS_WITH_DEEP_CHECKSUM: Dict[str, callable] = {}

def normalize_prompt(prompt: str) -> str:
    """
    Normalize prompt string for consistent checksum computation.
    Apply this in BOTH registration and token minting.
    """
    if not prompt:
        return ""
    
    # 1. Strip leading/trailing whitespace
    normalized = prompt.strip()
    
    # 2. Normalize line endings (Windows \r\n vs Unix \n)
    normalized = normalized.replace('\r\n', '\n')
    
    # 3. Collapse multiple consecutive newlines into single newline
    import re
    normalized = re.sub(r'\n\s*\n', '\n', normalized)
    
    # 4. Strip whitespace from each line (optional, but helpful)
    lines = [line.strip() for line in normalized.split('\n')]
    normalized = '\n'.join(lines)
    
    # 5. Remove empty lines (optional, depends on your needs)
    lines = [line for line in lines if line]
    normalized = '\n'.join(lines)
    
    return normalized

def _prepare_tool(tool: Tool) -> Dict: 
    tool_dict: Dict = {
        "name": tool.name,
        "signature": tool.signature, 
        "description": tool.description
    }
    
    if tool.source_code:
        tool_dict["source_code"] = tool.source_code
    
    return tool_dict

def compute_agent_checksum(agent_components: AgentComponents) -> str:
        """
        Compute deterministic checksum for agent
        """
        components = {
            "id": agent_components.agent_id,
            "prompt": normalize_prompt(agent_components.prompt_template),
            "tools": sorted([
                _prepare_tool(tool) for tool in agent_components.tools
            ], key=lambda x: x["name"]),
            "config": agent_components.configuration
        }
        content = json.dumps(components, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()

def to_agent_components_1(agent_spec: AgentSpec) -> AgentComponents: 
    return AgentComponents(
        agent_id=agent_spec.agent_id, 
        prompt_template=agent_spec.prompt, 
        tools=[Tool(
            name=toolname, 
            signature=str(inspect.signature(toolfunc)), 
            description=toolfunc.__doc__ 
        ) for toolname, toolfunc in agent_spec.tools_map.items()]
    )

def remove_docstrings(tree: ast.AST) -> None:
    """
    Remove docstring nodes from AST in-place.
    
    Docstrings are captured separately in checksum computation,
    so we remove them from implementation to avoid duplication.
    
    Args:
        tree: AST tree to modify
    """
    for node in ast.walk(tree):
        # Check if node can have a body with docstring
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, 
                            ast.ClassDef, ast.Module)):
            if (node.body and 
                isinstance(node.body[0], ast.Expr) and
                isinstance(node.body[0].value, ast.Constant) and
                isinstance(node.body[0].value.value, str)):
                # This is a docstring - we need to remove it
                node.body = node.body[1:] if len(node.body) > 1 else [ast.Pass()]

def normalize_source(source_code: str) -> str:
    """
    Normalize Python source code using AST.
    
    This ensures that formatting changes don't affect checksums
    while logic changes are always detected.
    
    Strips:
        - Comments (not part of execution logic)
        - Formatting differences (whitespace, indentation)
        - Docstrings (captured separately in checksum)
    
    Preserves:
        - All execution logic
        - Variable names (semantically significant)
        - Control flow structures
        - Function calls and their arguments
    
    Args:
        source_code: Raw Python source code
        
    Returns:
        Normalized source code in canonical form
        
    Examples:
        >>> # These produce IDENTICAL normalized output:
        >>> code1 = "def f(x):\\n    return x + 1"
        >>> code2 = "def f(x): return x+1  # comment"
        >>> normalize_source(code1) == normalize_source(code2)
        True
        
        >>> # These produce DIFFERENT normalized output:
        >>> code3 = "def f(x):\\n    return x + 2"
        >>> normalize_source(code1) != normalize_source(code3)
        True
    """
    # Remove leading indentation
    source = textwrap.dedent(source_code)
    
    try:
        # Parse to AST (Abstract Syntax Tree)
        tree = ast.parse(source)
        
        # Remove docstrings (we capture them separately)
        remove_docstrings(tree)
        
        # Unparse to canonical form
        # ast.unparse() produces deterministic, normalized output
        normalized = ast.unparse(tree)
        
        return normalized
        
    except SyntaxError:
        # If code has syntax errors, return as-is
        # This will cause checksum mismatch (which is correct)
        return source

def sourcecode(func: callable) -> str | None : 
    try: 
        source: str = inspect.getsource(func)
        normalized: str = normalize_source(source)
        return normalized
    except (OSError, TypeError): 
        return None

def _func_in_deep_tools(func: callable): 
    return func in _TOOLS_WITH_DEEP_CHECKSUM.values()

def to_agent_components(agent: ReActAgent) -> AgentComponents: 
    return AgentComponents(
        agent_id=agent.id, 
        prompt_template=agent.prompt, 
        tools=[Tool(
            name=name,
            signature=str(get_core_signature(func)), 
            description=description, 
            source_code=sourcecode(func) if _func_in_deep_tools(func) else None,
            is_agent=is_agent
        ) for func, name, description, is_agent in [(spec.original_func, spec.name, spec.description, spec.is_agent) for spec in agent.real_tool_specs()]]
    )

def get_core_signature(func) -> str:
    """
    Get function signature with wrapper parameters removed.
    Works even when the function can't be unwrapped.
    """
    import inspect
    
    # Try to unwrap what we can
    current = func
    try:
        current = inspect.unwrap(func)
    except (ValueError, AttributeError):
        pass
    
    # If still has wrapper attrs, try aggressive unwrap
    if hasattr(current, 'func'):
        current = current.func
    
    sig = inspect.signature(current)
    
    # Known wrapper parameters to filter out
    WRAPPER_PARAMS = {
        'config', 'callbacks', 'run_manager', 'tags', 'metadata',
        'run_id', 'parent_run_id', 'configurable', 'recursion_limit'
    }
    
    # Build cleaned parameter list
    cleaned_params = []
    found_var_keyword = False
    
    for name, param in sig.parameters.items():
        # Skip known wrapper params
        if name in WRAPPER_PARAMS:
            continue
        
        # Skip VAR_KEYWORD (**)  if it looks like a wrapper catchall
        if param.kind == inspect.Parameter.VAR_KEYWORD:
            found_var_keyword = True
            continue
        
        # Skip VAR_POSITIONAL (*) used by wrappers
        if param.kind == inspect.Parameter.VAR_POSITIONAL and name == 'args':
            continue
        
        cleaned_params.append(param)
    
    # Create new signature
    new_sig = inspect.Signature(
        cleaned_params,
        return_annotation=sig.return_annotation
    )
    
    return str(new_sig)
