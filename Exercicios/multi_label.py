from pattern import Pattern
from label import Label
from typing import Dict, List, Set
import copy


class MultiLabel:

    """
    Tracks multiple vulnerabilities simultaneously by managing a collection of
    Pattern-specific Label objects.
    """

    def __init__(self, patterns: List[Pattern], name: str=""):
        self._name = name
        
        #{pattern_object: Label_object}
        self._pattern_labels: Dict[Pattern, Label] = {}
        for pattern in patterns:
            self._pattern_labels[pattern] = Label(f"{name}_pattern.name")

    def add_source(self, source: str): 
        """
        Adds a source only to labels for patterns where this source name is valid.
        Ignores patterns where the source is not defined.
        """        
        for pattern, label in self._pattern_labels.items():
            if pattern.is_source(source):
                label.add_source(source)


    def add_sanitizer(self, sanitizer: str):
        """
        Adds a sanitizer only to labels for patterns where this sanitizer name is valid.
        Ignores patterns where the sanitizer is not defined.    
        """
        for pattern, label in self._pattern_labels.items():
            if pattern.is_sanitizer(sanitizer):
                label.add_sanitizer(sanitizer)

    def get_label_for_pattern(self, pattern: Pattern) -> Label:
        """
        Returns a deep copy of the label for a specific pattern.
        Returns empty label if pattern not tracked.
        """
        return copy.deepcopy(self._pattern_labels.get(pattern, Label()))

    def get_all_labels(self) -> Dict[Pattern, Label]:
        """Returns a deep copy of all pattern-label mappings."""
        return copy.deepcopy(self._pattern_labels)

    def get_patterns(self) -> List[Pattern]:
        """Returns a list of all patterns being tracked."""
        return list(self._pattern_labels.keys())

    def has_vulnerability(self, pattern: Pattern, sink: str) -> bool:
        """
        Checks if this multilabel indicates a vulnerability for a given pattern and sink.
        """
        if pattern not in self._pattern_labels:
            return False

        label = self._pattern_labels[pattern]
        for source in label.get_sources():
            if pattern.is_source(source) and pattern.is_sink(sink):
                if label.has_direct_flow_from(source):
                    return True

        return False

    def combine_with(self, other: 'MultiLabel') -> 'MultiLabel':
        """
        Combines this MultiLabel with another, creating an independent new one.
        
        For each pattern present in either MultiLabel, the corresponding labels are combined.
        Patterns only in one MultiLabel are copied directly.
        """

        #Union of patterns from both multilabels
        all_patterns = list(set(self._pattern_labels.keys())) | set(other._pattern_labels.keys())

        #Create new multilabel
        result = MultiLabel(all_patterns, f"({self._name} + {other._name})")

        #For each pattern combine with corresponding labels
        for pattern in all_patterns:
            label1 = self._pattern_labels.get(pattern, Label())
            label2 = other._pattern_labels.get(pattern, Label())

            #Combine them and replace in result
            result._pattern_labels[pattern] = label1.combine_with(label2)

        return result

    def __str__(self) -> str:
        """String representation showing labels for each pattern."""
        if not self._pattern_labels:
            return f"MultiLabel[{self._name or 'unnamed'}]: (empty)"
        
        parts = [f"MultiLabel[{self._name or 'unnamed'}]:"]
        for pattern in sorted(self._pattern_labels.keys(), key=lambda p: p.name):
            label = self._pattern_labels[pattern]
            parts.append(f"  [{pattern.name}]: {label}")
        return "\n".join(parts)



if __name__ == "__main__":
    # Define vulnerability patterns
    sql_pattern = Pattern(
        vul_name="SQL Injection",
        sources=["$_GET", "$_POST"],
        sanitizers=["prepare()", "mysql_real_escape_string()"],
        sinks=["mysql_query()", "execute()"]
    )
    
    path_pattern = Pattern(
        vul_name="Path Traversal",
        sources=["$_GET", "$_POST"],
        sanitizers=["basename()", "realpath()"],
        sinks=["open()", "include()"]
    )
    
    # Create MultiLabel tracking both vulnerabilities
    multilabel = MultiLabel([sql_pattern, path_pattern], "user_data")
    
    # Add source - applies to both patterns
    multilabel.add_source("$_GET")
    
    # Add SQL sanitizer - only affects SQL pattern
    multilabel.add_sanitizer("mysql_real_escape_string()")
    
    # Add path sanitizer - only affects Path pattern
    multilabel.add_sanitizer("basename()")
    
    print(multilabel)
    # Output shows:
    #   SQL Injection: $_GET→{mysql_real_escape_string()}
    #   Path Traversal: $_GET→{basename}
    
    # Check vulnerabilities
    print(f"\nSQL vul via execute(): {multilabel.has_vulnerability(sql_pattern, 'execute()')}")  # False
    print(f"Path vul via open(): {multilabel.has_vulnerability(path_pattern, 'open()')}")      # False
    
    # Demonstrate inappropriate sanitizer
    bad_label = MultiLabel([sql_pattern, path_pattern], "bad_data")
    bad_label.add_source("$_POST")
    bad_label.add_sanitizer("mysql_real_escape_string()")  # Only for SQL!
        
    print(f"\nPath vul via open(): {bad_label.has_vulnerability(path_pattern, 'open()')}")  # True!
    # Path pattern shows: $_POST→∅ (no sanitizers applied)
    
