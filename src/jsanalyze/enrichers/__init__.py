"""Optional external-tool enrichers.

Each enricher runs a third-party CLI on the LOCAL decoded JS (never the target),
is skipped gracefully when its tool is absent or disabled in config, and returns
records in the shapes documented on :class:`jsanalyze.models.AnalysisResult`.

Network-touching behaviour (fetching a remote .map, verifying a secret against a
provider, GraphQL introspection) stays OFF unless ``cfg['allow_network']`` is true
— that is the Operator Gate.
"""
