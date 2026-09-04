"""Offline PSL matching for corpus split grouping, including private rules.

Implements longest-rule, wildcard and exception precedence. No network refresh.
The caller must verify/pin the UTF-8 snapshot before constructing this class.
"""
class PublicSuffixList:
    def __init__(self, text):
        self.exact, self.wildcards, self.exceptions = set(), set(), set()
        for line in text.splitlines():
            value = line.strip().split()
            if not value or value[0].startswith("//"):
                continue
            rule = value[0].lower()
            destination = self.exact
            if rule.startswith("!"):
                rule, destination = rule[1:], self.exceptions
            elif rule.startswith("*."):
                rule, destination = rule[2:], self.wildcards
            if "*" in rule or "!" in rule or not rule:
                raise ValueError("Invalid public suffix rule")
            rule = rule.encode("idna").decode("ascii")
            destination.add(rule)
        if not self.exact:
            raise ValueError("Public suffix snapshot has no exact rules")

    def registrable_domain(self, domain):
        labels = domain.lower().rstrip(".").encode("idna").decode("ascii").split(".")
        suffix_length = 1  # PSL default '*' for unknown TLDs.
        for index in range(len(labels)):
            suffix = ".".join(labels[index:])
            length = len(labels) - index
            if suffix in self.exceptions:
                return ".".join(labels[-length:])
            if suffix in self.exact:
                suffix_length = max(suffix_length, length)
            if index > 0 and suffix in self.wildcards:
                suffix_length = max(suffix_length, length + 1)
        # A suffix-only name is kept as its own group; never dropped/relabelled.
        return ".".join(labels[-min(len(labels), suffix_length + 1):])
