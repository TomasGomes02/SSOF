class Pattern():

    def __init__(self, vul_name, sources, sanitizers, sinks):
        self.name = vul_name
        self.sources = set(sources)
        self.sanitizers = set(sanitizers)
        self.sinks = set(sinks)


    def get_name(self):
        return self.name

    def get_sources(self):
        return self.sources

    def get_sanitizers(self):
        return self.sanitizers 

    def get_sinks(self):
        return self.sinks
    
    def is_source(self, source):
        return source in self.sources

    def is_sanitizer(self, sanitizer):
        return sanitizer in self.sanitizers

    def is_sink(self, sink):
        return sink in self.sinks


    def __str__(self):
        return (f"Pattern[{self.name}]: "
                f"{len(self.sources)} sources, "
                f"{len(self.sanitizers)} sanitizers, "
                f"{len(self.sinks)} sinks")
    
    def __repr__(self):
        return (f"Pattern(name='{self.name}', "
                f"sources={self.sources}, "
                f"sanitizers={self.sanitizers}, "
                f"sinks={self.sinks})")

if __name__ == "__main__":

    sql_injection = Pattern(
        vul_name="SQL Injection",
        sources=["$_GET", "$_POST", "read_input()", "get_user_input()"],
        sanitizers=["mysql_real_escape_string()", "prepare_statement()", "intval()"],
        sinks=["mysql_query()", "execute()", "mysqli_query()"]
    )
    
    print(sql_injection)
    print(f"Is mysql_query() a sink? {sql_injection.is_sink('mysql_query()')}")
    print(f"Is $_GET a source? {sql_injection.is_source('$_GET')}")
    print(f"Is print() a sink? {sql_injection.is_sink('print()')}")
    
    print("\nAll sinks:", sql_injection.get_sinks())
