# SSOF

## Taint Analysis Tool: Patterns and Flow Labels

### Project Overview

This project involves developing a tool for detecting security vulnerabilities by tracking potentially dangerous information flows. The goal is to trace untrusted information from sources (e.g., user input) to sensitive sinks (e.g., database queries) and analyze whether these flows are neutralized by sanitizers.

This tool requires two main components:

    A system for defining vulnerability patterns (sources, sinks, sanitizers).

    An information flow policy using labels to track data integrity.

Tasks

1. Pattern Class

Develop a class Pattern that represents a single vulnerability pattern.

It should include at least the following basic operations: 

    (a) A constructor that receives a vulnerability name, a list of source names, a list of sanitizer names, and a list of sink names. 
    (b) Selectors (getters) for each of its components. 
    (c) Tests for checking whether a given name is a source, sanitizer, or sink for the pattern.

2. Label Class

Develop a class Label that represents the integrity of information carried by a resource. It must capture:

    The sources that might have influenced the information.

    Which sanitizers (if any) have intercepted the flow from each source.

It should include at least the following basic operations: 
  
    (a) A well-designed internal structure. (Note: A resource might be influenced by the same source in different ways. Is your label structure refined enough to distinguish these cases?) 
    (b) Constructors and operations for adding sources and applying sanitizers to the label. 
    (c) Selectors for each of its components. 
    (d) A combinor method that returns a new Label representing the combined integrity of two pieces of information.

    Note: Labels must be mutable. When combining, the new label should be independent of the original ones (i.e., a deep copy).

3. MultiLabel Class

Develop a class MultiLabel that generalizes the Label class to track multiple vulnerabilities at the same time.

    This class should be able to represent distinct labels corresponding to different vulnerability patterns (e.g., one label for "SQL Injection", one for "XSS").

    Include corresponding constructors, selectors, and a combinor.

    Important: When a source or sanitizer is added, it should only affect the labels for patterns where that name is relevant (e.l., a SQL sanitizer should only affect the SQL Injection label, not the XSS label).
