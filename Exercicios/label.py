from typing import Dict, Set
import copy

class Label:
    """
    Represents information flow integrity for a resource.
    Tracks which sources influenced data and which sanitizers were applied.
    """
    def __init__(self, name: str = ""):
        self._name = name
        # {source_name: {sanitizer1, sanitizer2, ...}}
        # Empty set means direct flow (unsanitized)
        self._flows: Dict[str, Set[str]] = {}


    def add_source(self, source: str):
        if source not in self._flows:
            self._flows[source] = set()
            
        
    def add_sanitizer(self, sanitizer: str):
        """
        Applies a sanitizer to ALL current flows.
        The sanitizer intercepts data after it leaves sources.
        
        Args:
            sanitizer: Name of sanitizer function
        """

        for source in self._flows:
            self._flows[source].add(sanitizer)


    def get_name(self) -> str:
        return self._name

    def get_flows(self) -> Dict[str, Set[str]]:
        return copy.deepcopy(self._flows)

    def get_sources(self) -> Set[str]:
        return set(self._flows.keys())
    
    def get_sanitizers_for_source(self, source: str) -> Set[str]:
        return self._flows.get(source, set()).copy()

    def has_direct_flow_from(self, source:str) -> bool:
        return source in self._flows and len(self._flows[source]) == 0

    def has_sanitized_flow_from(self, source:str) -> bool:
        return source in self._flows and len(self._flows[source]) > 0

    def combine_with(self, other: 'Label') -> 'label':
        """
        Combines this label with another to represent merged information.
        Creates an INDEPENDENT new label (mutable, no shared references).
        
        Args:
            other: Label to combine with
            
        Returns:
            New Label object
        """ 

        result = Label(f"({self._name} + {other._name})")

        #Deep copy this label's flow
        for source, sanitizers in self._flows.items():
            result._flows[source] = sanitizers.copy()

        #Merge other label's flows
        for source, sanitizers in other._flows.items():
            if source in result._flows:
                result._flows[source].update(sanitizers)
            else:
                result._flows[source] = sanitizers.copy()

        return result

    def __str__(self) -> str:
        flow_strs = []
        for src in sorted(self._flows.keys()):
            sanitizers = sorted(self._flows[src])
            if sanitizers:
                flow_strs.append(f"{src}→{{{', '.join(sanitizers)}}}")
            else:
                flow_strs.append(f"{src}→∅")
        
        return f"Label[{self._name or 'unnamed'}]: {'; '.join(flow_strs)}"


if __name__ == "__main__":

    # Example 1: Basic flow tracking
    input_label = Label("username")
    input_label.add_source("$_GET")      # Direct from user: {$_GET: ∅}
    print(input_label)                    # Label[username]: $_GET→∅

    #input_label.add_sanitizer("escape_sql")  # Sanitized: {$_GET: {escape_sql}}
    print(input_label)                    # Label[username]: $_GET→{escape_sql}

    # Example 2: Combining flows
    label1 = Label("data1")
    label1.add_source("db_query")
    label1.add_sanitizer("validate")

    label2 = Label("data2")
    label2.add_source("$_POST")

    combined = label1.combine_with(label2)
    print(combined)  # Label[(data1 + data2)]: $_POST→∅; db_query→{validate}
    # Note: New label is independent - modifying combined doesn't affect label1/label2

    # Example 3: Same source, different paths
    label3 = Label("mixed")
    label3.add_source("user_input")      # {user_input: ∅}
    label3.add_sanitizer("escape_html")  # {user_input: {escape_html}}
    label3.add_sanitizer("validate")     # {user_input: {escape_html, validate}}

    # Example 4: Checking for vulnerabilities
    if input_label.has_direct_flow_from("$_GET"):
        print("WARNING: Unsanitized user input!")  
